#!/usr/bin/env python3
"""Schema-v3 named-write conformance; existing v1/v2 suites stay unchanged."""
import argparse
import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

from run import (CORPUS, EXIT_CODES, decisions, digest, execute, fixture_path,
                 module_provenance, read_json, require, save, smt_decisions,
                 strict_json, strings, validate_contract as validate_get_contract,
                 validate_request as validate_get_request)
from run_read_access import (URL_KEYS, request_attributes, scope_matches, validate_url_result,
                             request_url as read_request_url, validate_contract as validate_read_contract,
                             validate_request as validate_read_request)

PROFILE = 'kubernetes-rbac-v1.34-read-write-v1'
WRITES = {'update': 'PUT', 'patch': 'PATCH', 'delete': 'DELETE'}


def validate_contract(contract):
    require(isinstance(contract, dict) and type(contract.get('schema_version')) is int
            and contract['schema_version'] == 3, 'Expected v3 contract')
    # Named writes have the named-get structural domain. This projection only
    # reuses input validation; it is never used to compare scopes or decisions.
    common = copy.deepcopy(contract)
    common['schema_version'] = 2
    require(isinstance(common.get('clauses'), list) and isinstance(common.get('change_scope'), list),
            'Missing v3 scopes')
    for scope in common['clauses'] + common['change_scope']:
        require(isinstance(scope, dict), 'Scope must be an object')
        if scope.get('verb') in WRITES:
            scope['verb'] = 'get'
    return validate_read_contract(common)


def normalize_contract(contract):
    validate_contract(contract)
    result = copy.deepcopy(contract)
    for identity in result['context']['identities']:
        identity['groups'].sort()
    result['context']['identities'].sort(key=lambda identity: identity['username'])
    for scope in result['clauses'] + result['change_scope']:
        if scope['names'] is not None:
            scope['names'].sort()
    changes = {json.dumps(scope, sort_keys=True): scope for scope in result['change_scope']}
    result['change_scope'] = [changes[key] for key in sorted(changes)]
    return result


def validate_request(request, identities):
    require(isinstance(request, dict), 'Request must be an object')
    projected = dict(request)
    if request.get('verb') in WRITES:
        projected['verb'] = 'get'
    validate_read_request(projected, identities)


def request_url(request):
    if request['verb'] not in WRITES:
        return read_request_url(request)
    return {key: request[key] for key in ['id', 'username', 'groups']} | {
        'method': WRITES[request['verb']],
        'url': '/api/v1/namespaces/' + quote(request['namespace'], safe='') + '/'
               + request['resource'] + '/' + quote(request['name'], safe='')}


def validate_report(execution, contract, expected):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected, 'Unexpected write CLI verdict')
    require(execution['returncode'] == EXIT_CODES[expected], 'CLI exit and verdict disagree')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Wrong report schema')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int
            and frozen['schema_version'] == 3 and frozen.get('kind') == contract['kind']
            and isinstance(frozen.get('canonical'), str), 'Missing v3 frozen identity')
    require(normalize_contract(strict_json(frozen['canonical'])) == normalize_contract(contract),
            'Reported contract differs from exact frozen v3 semantics')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == PROFILE, 'Wrong read-write profile')
    if expected in ['proved', 'violated']:
        require(assurance.get('status') == 'within_profile', 'Supported snapshot outside profile')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'unknown':
        require(isinstance(report.get('reason'), str) and report['reason'], 'Unknown lacks reason')
    return report


def witness_request(report, identities):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing write counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'}, 'Missing object dimensions')
    request = {'id': 'witness', 'username': witness.get('principal'), 'groups': witness.get('identity_groups'),
               'verb': witness.get('action'), 'apiGroup': '', 'resource': obj['resource_kind'],
               'namespace': obj['namespace'], 'name': obj['name'], 'resourceRequest': True, 'subresource': ''}
    validate_request(request, identities)
    require(strings(witness.get('granting_rules'), nonempty=True), 'Invalid witness grant labels')
    return request


def older_contract_controls(requests, contract):
    """Bind write rejections to a positive control differing only in verb/ID."""
    writes = [next((request for request in requests if request.get('verb') == verb), None) for verb in WRITES]
    require(all(request is not None for request in writes), 'Missing old-contract write boundary request')
    attributes = [{key: value for key, value in request.items() if key not in ['id', 'verb']} for request in writes]
    require(all(value == attributes[0] for value in attributes), 'Old-contract boundary requests differ beyond verb/ID')
    control = {**writes[0], 'id': 'older-get-control', 'verb': 'get'}
    version = contract.get('schema_version')
    require(type(version) is int and version in [1, 2], 'Expected an older contract for boundary control')
    if version == 1:
        validate_get_request(control, validate_get_contract(contract))
    else:
        validate_read_request(control, validate_read_contract(contract))
    return control, writes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--corpus', type=Path, default=CORPUS/'write-access')
    parser.add_argument('--demo', type=Path, default=CORPUS/'workflows/write-access')
    parser.add_argument('--z3', default=os.environ.get('Z3', 'z3'))
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    report = {'complete': False, 'profile': PROFILE, 'reference': 'Kubernetes v1.34.0',
              'matrix_comparisons': 0, 'url_matrix_comparisons': 0, 'url_extraction_checks': 0,
              'outside_domain_checks': 0, 'older_contract_domain_checks': 0, 'older_contract_positive_controls': 0,
              'contract_witness_replays': 0, 'preservation_witness_replays': 0,
              'witness_features': [], 'cases': {}, 'failures': [],
              'limits': ['Synthetic offline snapshots; frozen identities and completeness are assumptions',
                         'Initial request authorization attributes, not operation success or payload effects',
                         'Extra create authorization for apply and special deletion checks are outside this model']}
    save(args.output, report)
    try:
        report['reference_module'] = module_provenance(args.module_metadata)
        cases = read_json(args.corpus/'cases.json')
        require(isinstance(cases, dict) and '01-unsafe' in cases and '04-repaired' in cases, 'Missing fixture inventory')
        contract_path = args.corpus/'contracts/write-access.json'
        contract = read_json(contract_path)
        identities = validate_contract(contract)
        requests_path = args.corpus/'requests.json'
        requests = read_json(requests_path)
        require(isinstance(requests, list) and requests, 'Empty write matrix')
        for request in requests:
            validate_request(request, identities)
        require(len({r['id'] for r in requests}) == len(requests), 'Duplicate matrix IDs')
        url_cases = read_json(args.corpus/'url-cases.json')
        require(isinstance(url_cases, list) and url_cases and len({c['id'] for c in url_cases}) == len(url_cases),
                'Missing/duplicate URL cases')
        fixtures = {name: fixture_path(args.corpus/'fixtures', name) for name in cases}
        for name, expected in cases.items():
            require(set(expected) == {'sha256', 'supported', 'expected_contract', 'expected_clause', 'expected_preservation'},
                    'Unexpected fixture expectation schema')
            require(type(expected['supported']) is bool and expected['expected_contract'] in ['proved', 'violated', 'unknown']
                    and expected['supported'] is (expected['expected_contract'] != 'unknown')
                    and expected['expected_preservation'] in [None, 'not_reached', 'preserved', 'changed'],
                    'Invalid fixture expectation')
            require(digest(fixtures[name]) == expected['sha256'], 'Original write snapshot hash differs')
        demo_cases = {'unsafe': ('violated', 'not_reached'), 'partial-write-fix': ('violated', 'not_reached'),
                      'repaired': ('proved', 'preserved'), 'operator-regression': ('proved', 'changed'),
                      'deny-all': ('violated', 'not_reached')}
        demo_contract_path = args.demo/'contract.json'
        demo_contract = read_json(demo_contract_path)
        demo_identities = validate_contract(demo_contract)
        older_contracts = [CORPUS/'contracts/frontend-access.json', CORPUS/'read-access/contracts/read-access.json']
        paths = [args.corpus/'cases.json', args.corpus/'url-cases.json', requests_path, contract_path,
                 *fixtures.values(), demo_contract_path, *older_contracts,
                 *(args.demo/(name + '.json') for name in demo_cases)]
        hashes = {str(path): digest(path) for path in paths}
        report['input_sha256'] = hashes
        report['binary_sha256'] = {key: digest(getattr(args, key)) for key in ['reference', 'model', 'soundcheck']}
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 not found')
        artifacts = args.output.parent/'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        features = set()
        with tempfile.TemporaryDirectory(prefix='soundcheck-write-z3-') as tools:
            Path(tools, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=tools + os.pathsep + os.environ.get('PATH', ''))
            url_input = artifacts/'url-requests.json'
            save(url_input, [{key: case[key] for key in URL_KEYS} for case in url_cases])
            supported_urls, outside_urls = [], []
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
                        raise RuntimeError('Outside-domain fixture actually satisfies the model domain')
                    outside_urls.append(request)
            url_attributes_path = artifacts/'supported-url-attributes.json'
            save(url_attributes_path, supported_urls)

            def replay(manifest, frozen_path, request, folder, label):
                request_path = folder/(label + '-request.json')
                save(request_path, [request])
                url = request_url(request)
                url_path = folder/(label + '-url.json')
                save(url_path, [url])
                expected = {**url, 'expected_attributes': request_attributes(request, urlsplit(url['url']).path),
                            'field_selector_error': False, 'label_selector_error': False}
                via_url = execute([args.reference, '--request-urls', manifest, url_path],
                                  folder/(label + '-url-reference.json'), environment)
                upstream = validate_url_result(via_url, [expected])
                direct = execute([args.reference, manifest, request_path], folder/(label + '-reference.json'), environment)
                model = execute([args.model, manifest, frozen_path, request_path], folder/(label + '-model.json'), environment)
                concrete = decisions(model, [request], 'model')
                symbolic = smt_decisions(model, [request], folder, label, z3, environment)
                require(upstream == decisions(direct, [request], 'reference') == concrete == symbolic,
                        'Write witness URL/direct/concrete/SMT decisions differ')
                features.add(request['verb'])
                return upstream['witness']

            def check_cli(name, manifest, frozen_path, frozen, context, expected, baseline):
                folder = artifacts/name
                entry = report['cases'].setdefault(name, {})

                def replay_clause(value, label):
                    clause = value.get('clause')
                    require(isinstance(clause, dict), 'Missing violated clause')
                    candidates = [c for c in frozen['clauses'] if c['name'] == clause.get('name')]
                    require(len(candidates) == 1 and clause.get('kind') == candidates[0]['kind'], 'Wrong clause identity')
                    if expected.get('expected_clause') is not None:
                        require(clause['name'] == expected['expected_clause'], 'Wrong ordered failing clause')
                    request = witness_request(value, context)
                    require(scope_matches(candidates[0], request), 'Witness outside frozen clause')
                    wanted = 'Allow' if candidates[0]['kind'] == 'must_not_grant' else 'NoOpinion'
                    require(replay(manifest, frozen_path, request, folder, label) == wanted, 'Witness does not violate its clause')
                    report['contract_witness_replays'] += 1

                verified = validate_report(execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', frozen_path,
                                                    '--format', 'json'], folder/'verify.json', environment),
                                           frozen, expected['expected_contract'])
                entry['contract'] = verified['result']
                if verified['result'] == 'violated':
                    replay_clause(verified, 'verify-witness')
                preservation = expected['expected_preservation']
                if preservation is not None:
                    wanted = verified['result'] if verified['result'] != 'proved' else {
                        'preserved': 'proved', 'changed': 'violated'}[preservation]
                    compared = validate_report(execute([args.soundcheck, 'rbac', 'compare', baseline, manifest,
                                                       '--contract', frozen_path, '--format', 'json'],
                                                      folder/'compare.json', environment), frozen, wanted)
                    entry.update(comparison=compared['result'], preservation=preservation)
                    if verified['result'] != 'proved':
                        require(preservation == 'not_reached', 'Broken candidate cannot reach preservation')
                        if compared['result'] == 'violated':
                            replay_clause(compared, 'compare-contract-witness')
                    elif compared['result'] == 'violated':
                        require(compared.get('property') == 'rbac-repair-preservation'
                                and compared.get('clause', {}).get('name') == 'preservation-outside-change-scope'
                                and compared['clause'].get('kind') == 'must_preserve', 'Wrong preservation obligation')
                        request = witness_request(compared, context)
                        require(not any(scope_matches(scope, request) for scope in frozen['change_scope']),
                                'Preservation witness inside approved changes')
                        before = replay(baseline, frozen_path, request, folder, 'preservation-before')
                        after = replay(manifest, frozen_path, request, folder, 'preservation-after')
                        require(before != after, 'Preservation witness has no decision difference')
                        features.add('write-preservation' if request['verb'] in WRITES else 'read-preservation')
                        report['preservation_witness_replays'] += 2
                report['witness_features'] = sorted(features)
                print(f'{name}: {entry["contract"]}', flush=True)
                save(args.output, report)

            for name, expected in sorted(cases.items()):
                manifest, folder = fixtures[name], artifacts/name
                reference = execute([args.reference, manifest, requests_path], folder/'matrix-reference.json', environment)
                upstream = decisions(reference, requests, 'reference')
                model = execute([args.model, manifest, contract_path, requests_path], folder/'matrix-model.json', environment)
                concrete = decisions(model, requests, 'model', allow_unsupported=True)
                require((concrete is not None) is expected['supported'], 'Unexpected write support boundary')
                if concrete is not None:
                    symbolic = smt_decisions(model, requests, folder, 'matrix', z3, environment)
                    require(upstream == concrete == symbolic, f'Write matrix mismatch in {name}')
                    report['matrix_comparisons'] += len(requests)
                    urls = execute([args.reference, '--request-urls', manifest, url_input], folder/'url-reference.json', environment)
                    parsed = validate_url_result(urls, url_cases)
                    report['url_extraction_checks'] += len(url_cases)
                    url_model = execute([args.model, manifest, contract_path, url_attributes_path], folder/'url-model.json', environment)
                    url_concrete = decisions(url_model, supported_urls, 'model')
                    url_symbolic = smt_decisions(url_model, supported_urls, folder, 'url-matrix', z3, environment)
                    require({r['id']: parsed[r['id']] for r in supported_urls} == url_concrete == url_symbolic,
                            'URL-derived write decisions differ')
                    report['url_matrix_comparisons'] += len(supported_urls)
                check_cli(name, manifest, contract_path, contract, identities, expected, fixtures['01-unsafe'])

            for request in outside_urls:
                path = artifacts/'outside-domain'/(request['id'] + '.json')
                save(path, [request])
                model = execute([args.model, fixtures['04-repaired'], contract_path, path], path.with_suffix('.result.json'), environment)
                require(decisions(model, [request], 'model', allow_unsupported=True) is None,
                        'Outside write domain silently accepted')
                report['outside_domain_checks'] += 1
            for older_contract in older_contracts:
                frozen_old = read_json(older_contract)
                control, writes = older_contract_controls(requests, frozen_old)
                version = str(frozen_old['schema_version'])
                folder = artifacts/'old-contracts'
                control_path = folder/(version + '-get-control.json')
                save(control_path, [control])
                model = execute([args.model, fixtures['04-repaired'], older_contract, control_path],
                                control_path.with_suffix('.result.json'), environment)
                concrete = decisions(model, [control], 'model')
                symbolic = smt_decisions(model, [control], folder, version + '-get-control', z3, environment)
                reference = execute([args.reference, fixtures['04-repaired'], control_path],
                                    folder/(version + '-get-reference.json'), environment)
                require(concrete == symbolic == decisions(reference, [control], 'reference'),
                        'Older contract must support the identical named-get control before write rejection counts')
                report['older_contract_positive_controls'] += 1
                for request in writes:
                    path = folder/(version + '-' + request['verb'] + '.json')
                    save(path, [request])
                    model = execute([args.model, fixtures['04-repaired'], older_contract, path], path.with_suffix('.result.json'), environment)
                    require(decisions(model, [request], 'model', allow_unsupported=True) is None,
                            'An older contract silently gained a write request domain')
                    report['older_contract_domain_checks'] += 1
            for name, (verdict, preservation) in demo_cases.items():
                check_cli('demo-' + name, args.demo/(name + '.json'), demo_contract_path, demo_contract,
                          demo_identities, {'expected_contract': verdict, 'expected_preservation': preservation}, args.demo/'unsafe.json')
        require({'update', 'patch', 'delete', 'read-preservation', 'write-preservation'} <= features,
                'Missing planned write witness coverage')
        require(all(digest(Path(path)) == value for path, value in hashes.items()), 'Frozen input bytes changed')
        require(all(digest(getattr(args, key)) == value for key, value in report['binary_sha256'].items()),
                'Executables changed during run')
        report.update(complete=True, inputs_unchanged=True, binaries_unchanged=True)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print(json.dumps({key: report[key] for key in ['complete', 'matrix_comparisons', 'url_matrix_comparisons',
                                                  'url_extraction_checks', 'outside_domain_checks', 'older_contract_domain_checks',
                                                  'older_contract_positive_controls',
                                                  'contract_witness_replays', 'preservation_witness_replays', 'failures']}))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
