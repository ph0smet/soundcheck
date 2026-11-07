#!/usr/bin/env python3
"""Compare original RBAC snapshots and actual CLI witnesses with Kubernetes.

This is a conformance test, not a second implementation of authorization. It
checks request domains and contract scope, then delegates decisions to the
connector and the independently built upstream authorizer.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent
EXIT_CODES = {'proved': 0, 'violated': 3, 'unknown': 4, 'vacuous': 5, 'inconsistent': 6}
PROFILE = 'kubernetes-rbac-v1.34-get-v1'
DNS_LABEL = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
DNS_SUBDOMAIN = DNS_LABEL + r'(?:\.' + DNS_LABEL + r')*'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'Duplicate JSON key: {key}')
        result[key] = value
    return result


def strict_json(source):
    def invalid_constant(value):
        raise RuntimeError(f'Invalid JSON constant: {value}')
    return json.loads(source, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def read_json(path):
    return strict_json(path.read_bytes())


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + '\n')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def execute(argv, artifact, environment, json_output=True):
    started = time.monotonic()
    execution = {'command': [str(x) for x in argv]}
    try:
        completed = subprocess.run(execution['command'], capture_output=True, text=True,
                                   encoding='utf-8', errors='strict', timeout=60, env=environment)
        execution.update(returncode=completed.returncode, stdout=completed.stdout,
                         stderr=completed.stderr, seconds=time.monotonic() - started)
        save(artifact, execution)
        if json_output:
            execution['data'] = strict_json(completed.stdout)
        save(artifact, execution)
        return execution
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired, RuntimeError) as error:
        execution['error'] = str(error)
        save(artifact, execution)
        raise RuntimeError(f'Command/protocol failure; see {artifact}: {error}') from error


def strings(value, nonempty=False):
    return isinstance(value, list) and all(isinstance(x, str) and (x or not nonempty) for x in value)


def valid_dns(value, limit, pattern):
    return isinstance(value, str) and len(value) <= limit and re.fullmatch(pattern, value) is not None


def validate_contract(contract):
    require(isinstance(contract, dict) and set(contract) == {
        'schema_version', 'kind', 'context', 'clauses', 'change_scope'}, 'Unexpected contract schema')
    require(type(contract['schema_version']) is int and contract['schema_version'] == 1
            and contract['kind'] == 'kubernetes-rbac-access', 'Unexpected contract kind/version')
    context = contract['context']
    require(isinstance(context, dict) and set(context) == {'schema_version', 'snapshot_complete', 'identities'},
            'Unexpected fixed context schema')
    require(type(context['schema_version']) is int and context['schema_version'] == 1
            and context['snapshot_complete'] is True, 'Snapshot completeness must be explicitly assumed')
    require(isinstance(context['identities'], list) and context['identities'], 'Missing fixed identities')
    identities = {}
    for identity in context['identities']:
        require(isinstance(identity, dict) and set(identity) == {'username', 'groups'}, 'Invalid identity')
        username = identity['username']
        require(isinstance(username, str) and username and username not in identities, 'Invalid/duplicate username')
        groups = identity['groups']
        require(strings(groups, nonempty=True) and len(set(groups)) == len(groups), 'Invalid fixed groups')
        identities[username] = groups
    require(isinstance(contract['clauses'], list) and contract['clauses'], 'Missing frozen clauses')
    require(isinstance(contract['change_scope'], list), 'Missing frozen change scope')
    names = set()
    for is_clause, scopes in [(True, contract['clauses']), (False, contract['change_scope'])]:
        for scope in scopes:
            keys = {'subject', 'namespace', 'resource', 'names'} | ({'name', 'kind'} if is_clause else set())
            require(isinstance(scope, dict) and set(scope) == keys, 'Unexpected scope schema')
            require(isinstance(scope['subject'], str) and scope['subject'] in identities, 'Unknown scope identity')
            require(valid_dns(scope['namespace'], 63, DNS_LABEL), 'Invalid scope namespace')
            require(scope['resource'] in ['configmaps', 'secrets'], 'Unsupported scope resource')
            resource_names = scope['names']
            require(resource_names is None or (strings(resource_names, nonempty=True) and resource_names
                    and len(set(resource_names)) == len(resource_names)
                    and all(valid_dns(x, 253, DNS_SUBDOMAIN) for x in resource_names)), 'Invalid scope names')
            if is_clause:
                require(isinstance(scope['name'], str) and scope['name'] and scope['name'] not in names,
                        'Invalid/duplicate clause name')
                names.add(scope['name'])
                require(scope['kind'] in ['must_allow', 'must_not_grant'], 'Unsupported clause kind')
    require({clause['kind'] for clause in contract['clauses']} == {'must_allow', 'must_not_grant'},
            'The paired contract requires both allowance and no-grant clauses')
    return identities


def validate_request(request, identities):
    require(isinstance(request, dict) and set(request) == {
        'id', 'username', 'groups', 'verb', 'apiGroup', 'resource', 'namespace', 'name',
        'resourceRequest', 'subresource'}, 'Unexpected request schema')
    require(isinstance(request['id'], str) and request['id'], 'Invalid request ID')
    username = request['username']
    require(isinstance(username, str) and username in identities, 'Request identity outside fixed context')
    groups = request['groups']
    require(strings(groups, nonempty=True) and len(set(groups)) == len(groups)
            and sorted(groups) == sorted(identities[username]), 'Request groups differ from fixed context')
    require(request['verb'] == 'get' and request['apiGroup'] == ''
            and request['resourceRequest'] is True and request['subresource'] == '', 'Request outside fixed profile')
    require(request['resource'] in ['configmaps', 'secrets'], 'Request resource outside fixed profile')
    require(valid_dns(request['namespace'], 63, DNS_LABEL), 'Invalid request namespace')
    require(valid_dns(request['name'], 253, DNS_SUBDOMAIN), 'Invalid request name')


def validate_requests(requests, identities):
    require(isinstance(requests, list) and requests, 'Missing concrete request matrix')
    for request in requests:
        validate_request(request, identities)
    require(len({r['id'] for r in requests}) == len(requests), 'Duplicate request IDs')


def decisions(execution, requests, source, allow_unsupported=False):
    data = execution.get('data')
    require(isinstance(data, dict), f'{source}: response must be an object')
    if source == 'reference':
        valid = data.get('valid')
        errors = data.get('validation_errors')
        require(type(valid) is bool and strings(errors), 'reference: malformed validation envelope')
        if not valid:
            require(allow_unsupported and execution['returncode'] == 1 and errors
                    and data.get('decisions') == [], 'reference: invalid input cannot be a successful replay')
            return None
        require(not errors, 'reference: successful validation contains errors')
    else:
        require(data.get('status') in ['supported', 'unknown'], 'model: invalid support status')
        if data['status'] == 'unknown':
            require(allow_unsupported and execution['returncode'] == 0 and data.get('decisions') == []
                    and isinstance(data.get('reason'), str) and data['reason'], 'model: malformed unknown response')
            return None
    require(execution['returncode'] == 0, f'{source}: nonzero success status')
    rows = data.get('decisions')
    ids = [request['id'] for request in requests]
    require(len(set(ids)) == len(ids), 'Duplicate request IDs')
    require(isinstance(rows, list) and len(rows) == len(ids), f'{source}: missing or extra decisions')
    result = {}
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('id'), str)
                and row['id'] in ids and row['id'] not in result, f'{source}: missing/duplicate/unexpected decision ID')
        require(row.get('decision') in ['Allow', 'NoOpinion'], f'{source}: invalid RBAC decision')
        if source == 'reference':
            require(row.get('error') == '' and isinstance(row.get('reason'), str), 'reference: unresolved error')
        else:
            grants = row.get('grants')
            require(strings(grants, nonempty=True) and len(set(grants)) == len(grants), 'model: invalid grant labels')
            require(bool(grants) == (row['decision'] == 'Allow'), 'model: grant labels contradict the decision')
        result[row['id']] = row['decision']
    return result


def smt_result(execution, requests):
    require(execution.get('returncode') == 0, 'SMT matrix execution failed')
    require(execution.get('stderr', '') == '', 'SMT matrix emitted diagnostics')
    require(isinstance(execution.get('stdout'), str), 'SMT matrix output missing')
    values = execution['stdout'].split()
    require(len(values) == 2 * len(requests), 'SMT matrix returned missing/extra values')
    result = {}
    for index, request in enumerate(requests):
        domain, allowed = values[2 * index:2 * index + 2]
        require(domain == 'true' and allowed in ['true', 'false'], 'SMT matrix domain/evaluation is not a ground Boolean')
        require(request['id'] not in result, 'Duplicate SMT matrix request ID')
        result[request['id']] = 'Allow' if allowed == 'true' else 'NoOpinion'
    return result


def smt_decisions(model, requests, folder, label, z3, environment):
    script = model.get('data', {}).get('matrix_smt')
    require(isinstance(script, str) and script, 'Supported model response lacks production matrix_smt')
    path = folder/(label + '.smt2')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script)
    execution = execute([z3, '-smt2', path], folder/(label + '-smt.json'), environment, json_output=False)
    return smt_result(execution, requests)


def normalized_contract(contract):
    # These fields denote sets. Clause ordering is meaningful and retained.
    # Normalize both inputs independently of the connector's ordering choices.
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


def validate_report(execution, contract, expected):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected, f'Unexpected CLI verdict: {report}')
    require(execution['returncode'] == EXIT_CODES[expected], 'CLI exit code does not match verdict')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Unexpected report schema')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and frozen['schema_version'] == 1
            and frozen.get('kind') == contract['kind'] and isinstance(frozen.get('canonical'), str),
            'Missing frozen contract identity')
    require(normalized_contract(strict_json(frozen['canonical'])) == normalized_contract(contract),
            'Reported contract differs from frozen input')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == PROFILE,
            'Unexpected semantic profile')
    if expected in ['proved', 'violated']:
        require(assurance.get('status') == 'within_profile', 'Supported fixture is not within profile')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a counterexample')
    if expected == 'unknown':
        require(isinstance(report.get('reason'), str) and report['reason'], 'Unknown lacks a reason')
    return report


def scope_matches(scope, request):
    return (scope['subject'] == request['username'] and scope['namespace'] == request['namespace']
            and scope['resource'] == request['resource']
            and (scope['names'] is None or request['name'] in scope['names']))


def witness_request(report, identities):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing CLI counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'},
            'Missing typed object counterexample')
    request = {'id': 'witness', 'username': witness.get('principal'), 'groups': witness.get('identity_groups'),
               'verb': witness.get('action'), 'apiGroup': '', 'resource': obj['resource_kind'],
               'namespace': obj['namespace'], 'name': obj['name'], 'resourceRequest': True, 'subresource': ''}
    validate_request(request, identities)
    require(strings(witness.get('granting_rules'), nonempty=True), 'Missing counterexample grant labels')
    return request


def fixture_path(folder, name):
    require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]*', name), 'Unsafe case name')
    matches = [folder / (name + suffix) for suffix in ['.json', '.yaml'] if (folder / (name + suffix)).is_file()]
    require(len(matches) == 1, f'Expected exactly one original fixture for {name}')
    return matches[0]


def module_provenance(path):
    pins = read_json(HERE/'oracle/module-pins.json')
    actual = read_json(path)
    require(actual.get('Path') == 'k8s.io/kubernetes' and actual.get('Version') == 'v1.34.0'
            and actual.get('Sum') == pins['upstream_module_sum']
            and actual.get('GoModSum') == pins['upstream_go_mod_sum'], 'Upstream module pin/checksum mismatch')
    require(isinstance(actual.get('GoMod'), str)
            and digest(Path(actual['GoMod'])) == pins['upstream_go_mod_sha256'], 'Upstream go.mod checksum mismatch')
    if 'Origin' in actual:
        require(isinstance(actual['Origin'], dict) and actual['Origin'].get('Hash') == pins['upstream_commit'],
                'Upstream source revision mismatch')
    return {key: actual[key] for key in ['Path', 'Version', 'Sum', 'GoModSum']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--soundcheck', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, default=CORPUS/'fixtures')
    parser.add_argument('--cases', type=Path, default=CORPUS/'cases.json')
    parser.add_argument('--requests', type=Path, default=CORPUS/'requests.json')
    parser.add_argument('--contract', type=Path, default=CORPUS/'contracts/frontend-access.json')
    parser.add_argument('--baseline', default='01-unsafe')
    parser.add_argument('--z3', default=os.environ.get('Z3', 'z3'))
    parser.add_argument('--module-metadata', type=Path,
                        help='go mod download -json output; defaults beside --output')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    for key in ['reference', 'model', 'soundcheck', 'fixtures', 'cases', 'requests', 'contract']:
        setattr(args, key, getattr(args, key).resolve())
    report = {'complete': False, 'reference': 'Kubernetes v1.34.0 RBAC authorizer', 'cases': {},
              'matrix_comparisons': 0, 'matrix_components': ['concrete_connector', 'production_smt', 'kubernetes'],
              'contract_witness_replays': 0, 'preservation_witness_replays': 0,
              'failures': [], 'limits': ['Fixed complete snapshots and exact supplied identities/groups',
              'Named get requests for core ConfigMaps/Secrets', 'NoOpinion is not a final API-server denial',
              'Concrete matrix agreement is not a proof of encoder correctness']}
    save(args.output, report)
    try:
        report['reference_module'] = module_provenance(args.module_metadata or args.output.parent/'kubernetes-module.json')
        contract = read_json(args.contract)
        identities = validate_contract(contract)
        requests = read_json(args.requests)
        validate_requests(requests, identities)
        cases = read_json(args.cases)
        require(isinstance(cases, dict) and cases and args.baseline in cases, 'Invalid case inventory/baseline')
        files = {name: fixture_path(args.fixtures, name) for name in cases}
        fixed_paths = [args.cases, args.contract, args.requests] + list(files.values())
        hashes = {str(path): digest(path) for path in fixed_paths}
        for name, case in cases.items():
            require(isinstance(case, dict) and case.get('expected_contract') in EXIT_CODES
                    and case.get('expected_preservation') in [None, 'preserved', 'changed', 'unknown'],
                    f'Invalid case expectations: {name}')
            require(hashes[str(files[name])] == case.get('sha256'), f'Fixture hash mismatch: {name}')
        report['input_sha256'] = hashes
        report['binary_sha256'] = {key: digest(getattr(args, key)) for key in ['reference', 'model', 'soundcheck']}
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 executable not found')
        version = subprocess.run([z3, '-version'], capture_output=True, text=True, timeout=10, check=True)
        report['z3'] = version.stdout.strip()
        require(report['z3'].startswith('Z3 version '), 'Invalid Z3 version response')
        artifacts = args.output.parent/'artifacts'
        with tempfile.TemporaryDirectory(prefix='soundcheck-rbac-z3-') as tools:
            # The existing CLI invokes z3 by name. A fresh private link honors
            # Z3=/path/to/custom-binary without modifying any existing tool.
            Path(tools, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=tools + os.pathsep + os.environ.get('PATH', ''))

            def call_model(manifest, request_file, artifact):
                return execute([args.model, manifest, args.contract, request_file], artifact, environment)

            def replay(manifest, request, folder, label):
                request_file = folder/(label + '-request.json')
                save(request_file, [request])
                model = call_model(manifest, request_file, folder/(label + '-model.json'))
                reference = execute([args.reference, manifest, request_file], folder/(label + '-reference.json'), environment)
                mine = decisions(model, [request], 'model')
                upstream = decisions(reference, [request], 'reference')
                symbolic = smt_decisions(model, [request], folder, label, z3, environment)
                require(mine == symbolic == upstream, f'Counterexample replay mismatch: {label}')
                return upstream['witness']

            def replay_clause(result, manifest, folder, label):
                request = witness_request(result, identities)
                reported = result.get('clause')
                require(isinstance(reported, dict), 'Counterexample lacks clause identity')
                clauses = [clause for clause in contract['clauses'] if clause['name'] == reported.get('name')]
                require(len(clauses) == 1 and scope_matches(clauses[0], request), 'Counterexample outside frozen clause')
                require(reported.get('kind') == clauses[0]['kind'], 'Reported clause kind differs from the frozen requirement')
                wanted = 'NoOpinion' if clauses[0]['kind'] == 'must_allow' else 'Allow'
                require(replay(manifest, request, folder, label) == wanted, 'Counterexample does not violate its clause')
                report['contract_witness_replays'] += 1

            for name, expected in sorted(cases.items()):
                manifest = files[name]
                folder = artifacts/name
                entry = {'expected': expected, 'fixture_sha256': hashes[str(manifest)]}
                report['cases'][name] = entry
                reference = execute([args.reference, manifest, args.requests], folder/'matrix-reference.json', environment)
                upstream = decisions(reference, requests, 'reference', allow_unsupported=True)
                model = call_model(manifest, args.requests, folder/'matrix-model.json')
                mine = decisions(model, requests, 'model', allow_unsupported=True)
                entry['api_valid'] = upstream is not None
                entry['model_status'] = 'unknown' if mine is None else 'supported'
                if expected['expected_contract'] == 'unknown':
                    require(mine is None, f'Unknown fixture produced model decisions: {name}')
                else:
                    require(upstream is not None and mine is not None, f'Supported fixture was rejected: {name}')
                    symbolic = smt_decisions(model, requests, folder, 'matrix', z3, environment)
                    mismatches = [{'request': request, 'model': mine[request['id']], 'smt': symbolic[request['id']],
                                   'reference': upstream[request['id']]}
                                  for request in requests
                                  if not mine[request['id']] == symbolic[request['id']] == upstream[request['id']]]
                    entry['mismatches'] = mismatches
                    require(not mismatches, f'{name}: {len(mismatches)} request decision mismatches')
                    entry['matrix_comparisons'] = len(requests)
                    report['matrix_comparisons'] += len(requests)
                verification = execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', args.contract,
                                        '--format', 'json'], folder/'verify.json', environment)
                verified = validate_report(verification, contract, expected['expected_contract'])
                entry['contract'] = verified['result']
                if verified['result'] == 'violated':
                    replay_clause(verified, manifest, folder, 'verify-witness')
                preservation = expected['expected_preservation']
                if preservation is not None:
                    # The shipped comparison checks the candidate contract
                    # first. A broken candidate does not reach preservation.
                    wanted = verified['result'] if verified['result'] != 'proved' else {
                        'preserved': 'proved', 'changed': 'violated', 'unknown': 'unknown'}[preservation]
                    comparison = execute([args.soundcheck, 'rbac', 'compare', files[args.baseline], manifest,
                                          '--contract', args.contract, '--format', 'json'], folder/'compare.json', environment)
                    compared = validate_report(comparison, contract, wanted)
                    entry['comparison'] = compared['result']
                    if verified['result'] != 'proved':
                        entry['preservation'] = 'not_reached'
                        if compared['result'] == 'violated':
                            replay_clause(compared, manifest, folder, 'compare-contract-witness')
                    else:
                        entry['preservation'] = preservation
                        if compared['result'] == 'violated':
                            require(compared.get('property') == 'rbac-repair-preservation'
                                    and isinstance(compared.get('clause'), dict)
                                    and compared['clause'].get('name') == 'preservation-outside-change-scope'
                                    and compared['clause'].get('kind') == 'must_preserve',
                                    'Preservation report lacks the expected obligation')
                            request = witness_request(compared, identities)
                            require(not any(scope_matches(scope, request) for scope in contract['change_scope']),
                                    'Preservation witness is inside the approved change scope')
                            before = replay(files[args.baseline], request, folder, 'preservation-before')
                            after = replay(manifest, request, folder, 'preservation-after')
                            require(before != after, 'Preservation witness has no decision change')
                            report['preservation_witness_replays'] += 2
                print(f'{name}: {entry["contract"]}', flush=True)
                save(args.output, report)
        require(all(digest(Path(path)) == value for path, value in hashes.items()), 'Input bytes changed during execution')
        require(all(digest(getattr(args, key)) == value for key, value in report['binary_sha256'].items()),
                'Verifier/reference binaries changed during execution')
        report['inputs_unchanged'] = True
        report['binaries_unchanged'] = True
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print(json.dumps({key: report[key] for key in ['complete', 'matrix_comparisons', 'contract_witness_replays',
                                                'preservation_witness_replays', 'failures']}))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
