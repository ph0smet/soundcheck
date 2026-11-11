#!/usr/bin/env python3
"""Separate v2 read-access conformance with the upstream HTTP attribute boundary."""
import argparse
import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from run import (CORPUS, DNS_LABEL, DNS_SUBDOMAIN, EXIT_CODES, decisions, digest,
                 execute, fixture_path, module_provenance, read_json, require, save,
                 smt_decisions, strict_json, strings, valid_dns,
                 validate_contract as validate_v1_contract)

PROFILE = 'kubernetes-rbac-v1.34-read-v3'
REQUEST_KEYS = {'id', 'username', 'groups', 'verb', 'apiGroup', 'resource',
                'namespace', 'name', 'resourceRequest', 'subresource'}
URL_KEYS = {'id', 'username', 'groups', 'method', 'url'}
ATTRIBUTE_KEYS = REQUEST_KEYS - {'id'} | {'apiVersion', 'path'}


def validate_contract(contract):
    require(isinstance(contract, dict) and type(contract.get('schema_version')) is int
            and contract['schema_version'] == 2, 'Expected v2 contract')
    # Reuse only the legacy structural checks for common fields. Explicitly
    # validate the new dimensions before projecting them away for that check.
    common = copy.deepcopy(contract)
    common['schema_version'] = 1
    require(isinstance(common.get('clauses'), list) and isinstance(common.get('change_scope'), list),
            'Missing v2 scopes')
    for scope in common['clauses'] + common['change_scope']:
        require(isinstance(scope, dict) and scope.get('verb') in ['get', 'list', 'watch'],
                'Missing or unsupported scope verb')
        require('namespace' in scope, 'Namespace must be explicit, including null for all namespaces')
        if scope.get('namespace') is None:
            require(scope['verb'] != 'get', 'Named get cannot use the all-namespace endpoint')
            scope['namespace'] = 'all-namespace-placeholder'
        del scope['verb']
    return validate_v1_contract(common)


def normalize_contract(contract):
    validate_contract(contract)
    result = copy.deepcopy(contract)
    for identity in result['context']['identities']:
        identity['groups'].sort()
    result['context']['identities'].sort(key=lambda x: x['username'])
    for scope in result['clauses'] + result['change_scope']:
        if scope['names'] is not None:
            scope['names'].sort()
    changes = {json.dumps(scope, sort_keys=True): scope for scope in result['change_scope']}
    result['change_scope'] = [changes[key] for key in sorted(changes)]
    return result


def validate_request(request, identities):
    require(isinstance(request, dict) and set(request) == REQUEST_KEYS, 'Unexpected read request schema')
    require(isinstance(request['id'], str) and request['id'], 'Missing request ID')
    require(request['username'] in identities and strings(request['groups'], nonempty=True)
            and len(request['groups']) == len(set(request['groups']))
            and sorted(request['groups']) == sorted(identities[request['username']]),
            'Request does not use a frozen identity and exact groups')
    require(request['verb'] in ['get', 'list', 'watch'] and request['apiGroup'] == ''
            and request['resource'] in ['configmaps', 'secrets']
            and request['resourceRequest'] is True and request['subresource'] == '',
            'Request outside read profile')
    collection = request['verb'] != 'get'
    require((collection and request['namespace'] == '')
            or valid_dns(request['namespace'], 63, DNS_LABEL), 'Invalid namespace or all-namespace get')
    require((collection and request['name'] == '')
            or valid_dns(request['name'], 253, DNS_SUBDOMAIN), 'Invalid effective name or unnamed get')


def scope_matches(scope, request):
    return (scope['subject'] == request['username'] and scope['verb'] == request['verb']
            and (scope['namespace'] or '') == request['namespace']
            and scope['resource'] == request['resource']
            and (scope['names'] is None or request['name'] in scope['names']))


def validate_report(execution, contract, expected):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected, 'Unexpected read CLI verdict')
    require(execution['returncode'] == EXIT_CODES[expected], 'CLI exit and verdict disagree')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10,
            'Unexpected report schema')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int
            and frozen['schema_version'] == 2 and frozen.get('kind') == contract['kind']
            and isinstance(frozen.get('canonical'), str), 'Missing v2 frozen identity')
    require(normalize_contract(strict_json(frozen['canonical'])) == normalize_contract(contract),
            'Reported contract differs from frozen v2 input')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == PROFILE, 'Wrong read profile')
    if expected in ['proved', 'violated']:
        require(assurance.get('status') == 'within_profile', 'Supported snapshot outside profile')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'unknown':
        require(isinstance(report.get('reason'), str) and report['reason'], 'Unknown lacks a reason')
    return report


def witness_request(report, identities):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing read counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'},
            'Missing typed request dimensions')
    request = {'id': 'witness', 'username': witness.get('principal'), 'groups': witness.get('identity_groups'),
               'verb': witness.get('action'), 'apiGroup': '', 'resource': obj['resource_kind'],
               'namespace': obj['namespace'], 'name': obj['name'], 'resourceRequest': True, 'subresource': ''}
    validate_request(request, identities)
    require(strings(witness.get('granting_rules'), nonempty=True), 'Invalid witness grant labels')
    return request


def request_url(request):
    """A selected watch/list uses a collection URL, never a named-get URL."""
    path = '/api/v1/'
    if request['namespace']:
        path += 'namespaces/' + quote(request['namespace'], safe='') + '/'
    path += request['resource']
    query = {}
    if request['verb'] == 'get':
        path += '/' + quote(request['name'], safe='')
    else:
        if request['verb'] == 'watch':
            query['watch'] = 'true'
        if request['name']:
            query['fieldSelector'] = 'metadata.name=' + request['name']
    return {key: request[key] for key in ['id', 'username', 'groups']} | {
        'method': 'GET', 'url': path + ('?' + urlencode(query) if query else '')}


def request_attributes(request, path):
    return {key: value for key, value in request.items() if key != 'id'} | {'apiVersion': 'v1', 'path': path}


def validate_url_result(execution, cases):
    data = execution.get('data')
    require(isinstance(data, dict) and set(data) == {
        'schema_version', 'kind', 'valid', 'validation_errors', 'decisions'}
        and type(data['schema_version']) is int and data['schema_version'] == 1
        and data['kind'] == 'rbac_request_url_authorization', 'Unexpected URL adapter schema')
    outcomes = decisions(execution, cases, 'reference')
    rows = {row['id']: row for row in data['decisions']}
    for case in cases:
        row = rows[case['id']]
        require(set(row) == {'id', 'decision', 'reason', 'error', 'attributes',
                             'field_selector_error', 'label_selector_error'}, 'Unexpected URL decision schema')
        attributes = row['attributes']
        require(isinstance(attributes, dict) and set(attributes) == ATTRIBUTE_KEYS,
                'Missing projected authorization fields')
        require(type(attributes['resourceRequest']) is bool and strings(attributes['groups'])
                and all(isinstance(attributes[key], str) for key in ATTRIBUTE_KEYS - {'groups', 'resourceRequest'}),
                'Invalid projected authorization field types')
        require(attributes == case['expected_attributes'],
                f'Upstream request extraction differs for {case["id"]}: {attributes}')
        for key in ['field_selector_error', 'label_selector_error']:
            require(type(row[key]) is bool and row[key] is case[key], 'Selector parsing flag differs')
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--corpus', type=Path, default=CORPUS/'read-access')
    parser.add_argument('--demo', type=Path, default=CORPUS/'workflows/read-access')
    parser.add_argument('--z3', default=os.environ.get('Z3', 'z3'))
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    report = {'complete': False, 'profile': PROFILE, 'reference': 'Kubernetes v1.34.0',
              'matrix_comparisons': 0, 'url_matrix_comparisons': 0, 'url_extraction_checks': 0,
              'outside_domain_checks': 0, 'contract_witness_replays': 0, 'preservation_witness_replays': 0,
              'witness_features': [], 'cases': {}, 'failures': [],
              'limits': ['Synthetic offline fixed snapshots and identities; completeness is assumed',
                         'Actual RequestInfoFactory, explicit value projection, production RBAC authorizer',
                         'Authorization attributes do not establish storage selector validity, route existence, or final API denial']}
    save(args.output, report)
    try:
        report['reference_module'] = module_provenance(args.module_metadata)
        cases = read_json(args.corpus/'cases.json')
        require(isinstance(cases, dict) and '01-unsafe' in cases, 'Missing read fixture inventory')
        contract_paths = {name: args.corpus/'contracts'/(name + '.json')
                          for name in ['read-access', 'all-namespace', 'named-collections', 'operator-collection',
                                       'named-exclusions']}
        contracts = {name: read_json(path) for name, path in contract_paths.items()}
        identities = validate_contract(contracts['read-access'])
        require(all(validate_contract(value) == identities for value in contracts.values()), 'Different frozen identities')
        requests_path = args.corpus/'requests.json'
        requests = read_json(requests_path)
        require(isinstance(requests, list) and requests, 'Empty read matrix')
        for request in requests:
            validate_request(request, identities)
        require(len({r['id'] for r in requests}) == len(requests), 'Duplicate read matrix IDs')
        url_cases = read_json(args.corpus/'url-cases.json')
        require(isinstance(url_cases, list) and url_cases and len({c['id'] for c in url_cases}) == len(url_cases),
                'Missing/duplicate URL boundary cases')
        fixtures = {name: fixture_path(args.corpus/'fixtures', name) for name in cases}
        for name, expected in cases.items():
            require(set(expected) == {'sha256', 'contract', 'supported', 'expected_contract',
                                       'expected_clause', 'expected_preservation'}, 'Unexpected fixture expectation schema')
            require(expected['contract'] in contracts and type(expected['supported']) is bool
                    and expected['expected_contract'] in ['proved', 'violated', 'unknown']
                    and expected['supported'] is (expected['expected_contract'] != 'unknown')
                    and expected['expected_preservation'] in [None, 'not_reached', 'preserved', 'changed'],
                    'Invalid fixture expectations')
            require(digest(fixtures[name]) == expected['sha256'], 'Read fixture hash mismatch')
        # The public workflow is separately maintained. Its checks are explicit
        # and its exact source bytes are bound like the private conformance corpus.
        demo_cases = {'unsafe': ('violated', 'not_reached'), 'get-only-repair': ('violated', 'not_reached'),
                      'repaired': ('proved', 'preserved'), 'operator-regression': ('proved', 'changed'),
                      'deny-all': ('violated', 'not_reached')}
        demo_contract = read_json(args.demo/'contract.json')
        demo_identities = validate_contract(demo_contract)
        paths = [args.corpus/'cases.json', args.corpus/'url-cases.json', requests_path,
                 *contract_paths.values(), *fixtures.values(), args.demo/'contract.json',
                 *(args.demo/(name + '.json') for name in demo_cases)]
        hashes = {str(path): digest(path) for path in paths}
        report['input_sha256'] = hashes
        report['binary_sha256'] = {key: digest(getattr(args, key)) for key in ['reference', 'model', 'soundcheck']}
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 not found')
        artifacts = args.output.parent/'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        features = set()
        with tempfile.TemporaryDirectory(prefix='soundcheck-read-z3-') as tools:
            Path(tools, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=tools + os.pathsep + os.environ.get('PATH', ''))
            url_input = artifacts/'url-requests.json'
            save(url_input, [{key: c[key] for key in URL_KEYS} for c in url_cases])
            supported_urls = []
            outside_urls = []
            for case in url_cases:
                require(type(case.get('model_supported')) is bool, 'Missing URL domain expectation')
                request = {'id': case['id'], **{key: value for key, value in case['expected_attributes'].items()
                                              if key not in ['path', 'apiVersion']}}
                if case['model_supported']:
                    validate_request(request, identities)
                    supported_urls.append(request)
                else:
                    try:
                        validate_request(request, identities)
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError('Expected outside-domain URL is actually within domain')
                    outside_urls.append(request)
            supported_url_path = artifacts/'supported-url-attributes.json'
            save(supported_url_path, supported_urls)

            def replay(manifest, contract_path, request, folder, label):
                request_path = folder/(label + '-request.json')
                save(request_path, [request])
                url = request_url(request)
                url_path = folder/(label + '-url.json')
                save(url_path, [url])
                expected_url = {**url, 'expected_attributes': request_attributes(request, urlsplit(url['url']).path),
                                'field_selector_error': False, 'label_selector_error': False}
                via_url = execute([args.reference, '--request-urls', manifest, url_path],
                                  folder/(label + '-url-reference.json'), environment)
                upstream = validate_url_result(via_url, [expected_url])
                direct = execute([args.reference, manifest, request_path], folder/(label + '-reference.json'), environment)
                model = execute([args.model, manifest, contract_path, request_path], folder/(label + '-model.json'), environment)
                concrete = decisions(model, [request], 'model')
                symbolic = smt_decisions(model, [request], folder, label, z3, environment)
                require(upstream == decisions(direct, [request], 'reference') == concrete == symbolic,
                        'Witness URL/direct/concrete/SMT replay differs')
                features.add(request['verb'])
                if request['name'] == '':
                    features.add('empty-name')
                elif request['verb'] != 'get':
                    features.add('named-collection')
                if request['namespace'] == '':
                    features.add('all-namespace-' + request['verb'])
                return upstream['witness']

            def check_cli(name, manifest, contract_path, contract, frozen_identities, expected, baseline):
                folder = artifacts/name
                entry = report['cases'].setdefault(name, {})

                def replay_clause(value, label):
                    clause = value.get('clause')
                    require(isinstance(clause, dict), 'Missing violated clause')
                    candidates = [c for c in contract['clauses'] if c['name'] == clause.get('name')]
                    require(len(candidates) == 1 and clause.get('kind') == candidates[0]['kind'], 'Wrong violated clause')
                    if expected.get('expected_clause') is not None:
                        require(clause['name'] == expected['expected_clause'], 'Wrong ordered first failing clause')
                    request = witness_request(value, frozen_identities)
                    require(scope_matches(candidates[0], request), 'Witness outside its frozen clause')
                    wanted = 'Allow' if candidates[0]['kind'] == 'must_not_grant' else 'NoOpinion'
                    require(replay(manifest, contract_path, request, folder, label) == wanted, 'Witness does not violate clause')
                    report['contract_witness_replays'] += 1

                verified = validate_report(execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', contract_path,
                                                    '--format', 'json'], folder/'verify.json', environment),
                                           contract, expected['expected_contract'])
                entry['contract'] = verified['result']
                if verified['result'] == 'violated':
                    replay_clause(verified, 'verify-witness')
                preservation = expected['expected_preservation']
                if preservation is not None:
                    wanted = verified['result'] if verified['result'] != 'proved' else {
                        'preserved': 'proved', 'changed': 'violated'}[preservation]
                    compared = validate_report(execute([args.soundcheck, 'rbac', 'compare', baseline, manifest,
                                                       '--contract', contract_path, '--format', 'json'],
                                                      folder/'compare.json', environment), contract, wanted)
                    entry['comparison'] = compared['result']
                    entry['preservation'] = preservation
                    if verified['result'] != 'proved':
                        require(preservation == 'not_reached', 'Invalid candidate cannot reach preservation')
                        if compared['result'] == 'violated':
                            replay_clause(compared, 'compare-contract-witness')
                    elif compared['result'] == 'violated':
                        require(compared.get('property') == 'rbac-repair-preservation'
                                and compared.get('clause', {}).get('name') == 'preservation-outside-change-scope'
                                and compared['clause'].get('kind') == 'must_preserve', 'Wrong preservation obligation')
                        request = witness_request(compared, frozen_identities)
                        require(not any(scope_matches(scope, request) for scope in contract['change_scope']),
                                'Preservation witness inside approved change scope')
                        before = replay(baseline, contract_path, request, folder, 'preservation-before')
                        after = replay(manifest, contract_path, request, folder, 'preservation-after')
                        require(before != after, 'Preservation witness has no real decision change')
                        report['preservation_witness_replays'] += 2
                print(f'{name}: {entry["contract"]}', flush=True)
                report['witness_features'] = sorted(features)
                save(args.output, report)

            for name, expected in sorted(cases.items()):
                manifest = fixtures[name]
                folder = artifacts/name
                contract_path = contract_paths[expected['contract']]
                reference = execute([args.reference, manifest, requests_path], folder/'matrix-reference.json', environment)
                upstream = decisions(reference, requests, 'reference')
                model = execute([args.model, manifest, contract_path, requests_path], folder/'matrix-model.json', environment)
                concrete = decisions(model, requests, 'model', allow_unsupported=True)
                require((concrete is not None) is expected['supported'], 'Unexpected model support boundary')
                if concrete is not None:
                    symbolic = smt_decisions(model, requests, folder, 'matrix', z3, environment)
                    require(upstream == concrete == symbolic, f'Read matrix mismatch in {name}')
                    report['matrix_comparisons'] += len(requests)
                    urls = execute([args.reference, '--request-urls', manifest, url_input], folder/'url-reference.json', environment)
                    parsed = validate_url_result(urls, url_cases)
                    report['url_extraction_checks'] += len(url_cases)
                    url_model = execute([args.model, manifest, contract_path, supported_url_path], folder/'url-model.json', environment)
                    url_concrete = decisions(url_model, supported_urls, 'model')
                    url_symbolic = smt_decisions(url_model, supported_urls, folder, 'url-matrix', z3, environment)
                    require({r['id']: parsed[r['id']] for r in supported_urls} == url_concrete == url_symbolic,
                            'URL-derived model decisions differ')
                    report['url_matrix_comparisons'] += len(supported_urls)
                check_cli(name, manifest, contract_path, contracts[expected['contract']], identities,
                          expected, fixtures['01-unsafe'])

            # Boundary values are real upstream attributes, not supported model
            # requests. Require explicit unknown without partial decisions.
            for request in outside_urls:
                path = artifacts/'outside-domain'/(request['id'] + '.json')
                save(path, [request])
                model = execute([args.model, fixtures['03-repaired'], contract_paths['read-access'], path],
                                path.with_suffix('.result.json'), environment)
                require(decisions(model, [request], 'model', allow_unsupported=True) is None,
                        'Outside-domain URL was silently normalized into support')
                report['outside_domain_checks'] += 1
            for name, (verdict, preservation) in demo_cases.items():
                check_cli('demo-' + name, args.demo/(name + '.json'), args.demo/'contract.json', demo_contract,
                          demo_identities, {'expected_contract': verdict, 'expected_preservation': preservation},
                          args.demo/'unsafe.json')
        require({'get', 'list', 'watch', 'empty-name', 'named-collection',
                 'all-namespace-list', 'all-namespace-watch'} <= features, 'Missing planned witness boundary coverage')
        require(all(digest(Path(path)) == value for path, value in hashes.items()), 'Frozen input bytes changed')
        require(all(digest(getattr(args, key)) == value for key, value in report['binary_sha256'].items()),
                'Executables changed during run')
        report.update(complete=True, inputs_unchanged=True, binaries_unchanged=True)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print(json.dumps({key: report[key] for key in ['complete', 'matrix_comparisons', 'url_matrix_comparisons',
                                                  'url_extraction_checks', 'outside_domain_checks',
                                                  'contract_witness_replays', 'preservation_witness_replays', 'failures']}))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
