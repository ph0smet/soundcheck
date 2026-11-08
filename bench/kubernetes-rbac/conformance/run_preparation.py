#!/usr/bin/env python3
"""Independent preparation conformance, separate from the original RBAC matrix."""
import argparse
import copy
import hashlib
import os
import re
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, PROFILE, decisions, digest, execute, fixture_path,
                 module_provenance, read_json, require, save, scope_matches,
                 smt_decisions, strict_json, strings, validate_contract,
                 validate_report, validate_requests, witness_request)

OBJECT_FIELDS = {
    'uid', 'resourceVersion', 'selfLink', 'generation', 'creationTimestamp',
    'generateName', 'deletionTimestamp', 'deletionGracePeriodSeconds',
    'ownerReferences', 'finalizers', 'managedFields'}
LIST_FIELDS = {'resourceVersion', 'selfLink', 'continue', 'remainingItemCount'}
HASH = re.compile(r'[0-9a-f]{64}')
REMOVAL = re.compile(r'manifest(?:\.items\[([0-9]+)\])?\.metadata\.([A-Za-z]+)')


def byte_hash(value):
    return hashlib.sha256(value).hexdigest()


def validate_transformation(original, prepared, removed_fields):
    """Independent byte-to-AST check: delete only the inventory's fixed paths."""
    require(strings(removed_fields) and removed_fields == sorted(set(removed_fields)),
            'Removal inventory must be sorted and unique')
    expected = copy.deepcopy(strict_json(original))
    actual = strict_json(prepared)
    require(isinstance(expected, dict) and isinstance(expected.get('items'), list),
            'Original preparation input must have an explicit item array')
    for path in removed_fields:
        match = REMOVAL.fullmatch(path)
        require(match is not None, 'Unsafe removal path')
        index, key = match.groups()
        if index is None:
            require(key in LIST_FIELDS, 'Removal is not approved List metadata')
            container = expected
        else:
            require(key in OBJECT_FIELDS and int(index) < len(expected['items']),
                    'Removal is not approved object metadata')
            container = expected['items'][int(index)]
        require(isinstance(container, dict) and isinstance(container.get('metadata'), dict)
                and key in container['metadata'], 'Removal does not identify an original field')
        del container['metadata'][key]
    require(actual == expected, 'Prepared snapshot changed data beyond the fixed metadata removals')
    require(prepared.endswith(b'\n') and not prepared.endswith(b'\n\n'),
            'Prepared output must retain its single final newline')
    return len(expected['items'])


def validate_receipt(receipt, original, prepared, removed_fields):
    require(isinstance(receipt, dict) and set(receipt) == {
        'schema_version', 'kind', 'target_profile', 'input', 'snapshot', 'object_count',
        'removed_fields', 'verification_performed', 'completeness_established'},
        'Unexpected preparation receipt schema')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['kind'] == 'rbac-snapshot-preparation'
            and receipt['target_profile'] == PROFILE, 'Unexpected preparation receipt identity')
    require(receipt['verification_performed'] is False and receipt['completeness_established'] is False,
            'Preparation cannot establish verification or completeness')
    for key, source in [('input', original), ('snapshot', prepared)]:
        value = receipt[key]
        require(isinstance(value, dict) and set(value) == {'sha256', 'bytes'},
                'Unexpected preparation digest schema')
        require(value['sha256'] == byte_hash(source) and type(value['bytes']) is int
                and value['bytes'] == len(source), 'Preparation digest/length differs from exact bytes')
    object_count = validate_transformation(original, prepared, removed_fields)
    require(type(receipt['object_count']) is int and receipt['object_count'] == object_count,
            'Preparation object count changed')
    require(receipt['removed_fields'] == removed_fields, 'Receipt differs from independently fixed removals')


def validate_policy_comparison(execution, original, prepared, equal=True):
    value = execution.get('data')
    require(isinstance(value, dict) and set(value) == {
        'schema_version', 'kind', 'valid', 'original_sha256', 'prepared_sha256',
        'policy_equal', 'original_policy_sha256', 'prepared_policy_sha256',
        'original_objects', 'prepared_objects', 'validation_errors', 'differences'},
        'Unexpected typed-policy comparison schema')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == 'typed_rbac_policy_comparison', 'Unexpected policy comparison identity')
    require(value['valid'] is True and value['validation_errors'] == [],
            'Invalid original/prepared input cannot establish policy preservation')
    require(value['original_sha256'] == byte_hash(original)
            and value['prepared_sha256'] == byte_hash(prepared), 'Policy comparator read different inputs')
    require(value['policy_equal'] is equal and execution['returncode'] == (0 if equal else 1),
            'Typed-policy comparison outcome/exit mismatch')
    for key in ['original_policy_sha256', 'prepared_policy_sha256']:
        require(isinstance(value[key], str) and HASH.fullmatch(value[key]), 'Missing typed-policy digest')
    for key in ['original_objects', 'prepared_objects']:
        require(type(value[key]) is int and value[key] >= 0, 'Invalid typed-policy object count')
    require(strings(value['differences']) and bool(value['differences']) is (not equal),
            'Policy differences disagree with outcome')
    require((value['original_policy_sha256'] == value['prepared_policy_sha256']) is equal,
            'Typed-policy digests disagree with outcome')
    if equal:
        require(value['original_objects'] == value['prepared_objects'], 'Policy object inventory changed')
    return value


def mutate(snapshot, name):
    changed = copy.deepcopy(snapshot)
    if name == 'drop-binding':
        index = next(i for i, item in enumerate(changed['items']) if item['kind'] == 'RoleBinding')
        del changed['items'][index]
    elif name == 'widen-resource-names':
        rule = next(rule for item in changed['items'] for rule in item.get('rules', [])
                    if rule.get('resourceNames'))
        del rule['resourceNames']
    elif name == 'change-subject':
        subject = next(item['subjects'][0] for item in changed['items'] if item.get('subjects'))
        subject['name'] += '-changed'
    elif name == 'change-annotation':
        changed['items'][0]['metadata']['annotations']['fixture.soundcheck.dev/review'] = 'changed'
    elif name == 'add-unobserved-verb':
        rule = next(rule for item in changed['items'] for rule in item.get('rules', []) if rule.get('verbs'))
        rule['verbs'].append('watch')
    else:
        raise RuntimeError('Unknown corruption control')
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--soundcheck', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, default=CORPUS/'preparation/fixtures')
    parser.add_argument('--cases', type=Path, default=CORPUS/'preparation/cases.json')
    parser.add_argument('--requests', type=Path, default=CORPUS/'requests.json')
    parser.add_argument('--contract', type=Path, default=CORPUS/'contracts/frontend-access.json')
    parser.add_argument('--baseline', default='01-export-unsafe')
    parser.add_argument('--z3', default=os.environ.get('Z3', 'z3'))
    parser.add_argument('--module-metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for key in ['reference', 'model', 'soundcheck', 'fixtures', 'cases', 'requests',
                'contract', 'module_metadata', 'output']:
        setattr(args, key, getattr(args, key).resolve())
    report = {
        'complete': False, 'reference': 'Kubernetes v1.34.0 RBAC authorizer',
        'preparation_cases': {}, 'accepted_preparations': 0, 'rejected_preparations': 0,
        'typed_policy_comparisons': 0, 'preparation_matrix_comparisons': 0,
        'matrix_components': ['kubernetes_original', 'kubernetes_prepared', 'concrete_connector', 'production_smt'],
        'contract_witness_replays': 0, 'preservation_witness_replays': 0,
        'upstream_witness_calls': 0, 'corruption_controls': {}, 'failures': [],
        'limits': ['Synthetic offline fixtures; no cluster or general export support',
                   'Completeness and fixed identities remain external assumptions',
                   'Preparation is not verification or an independently checked semantic proof']}
    save(args.output, report)
    try:
        report['reference_module'] = module_provenance(args.module_metadata)
        contract = read_json(args.contract)
        identities = validate_contract(contract)
        requests = read_json(args.requests)
        validate_requests(requests, identities)
        cases = read_json(args.cases)
        require(isinstance(cases, dict) and args.baseline in cases, 'Missing preparation inventory/baseline')
        originals = {name: fixture_path(args.fixtures, name) for name in cases}
        paths = [args.cases, args.contract, args.requests] + list(originals.values())
        hashes = {str(path): digest(path) for path in paths}
        for name, case in cases.items():
            require(case.get('expected_preparation') in ['prepared', 'rejected']
                    and type(case.get('reference_valid')) is bool, 'Invalid preparation expectation')
            require(hashes[str(originals[name])] == case.get('sha256'), 'Original fixture hash mismatch')
            require(strings(case.get('removed_fields')), 'Missing fixed removal inventory')
            if case['expected_preparation'] == 'prepared':
                require(case['reference_valid'] is True
                        and case.get('expected_contract') in ['proved', 'violated']
                        and case.get('expected_preservation') in [None, 'preserved', 'changed'],
                        'Prepared fixture needs original validity and concrete verdict expectations')
            else:
                require(case.get('expected_contract') is None and case.get('expected_preservation') is None
                        and case['removed_fields'] == [], 'Rejected preparation cannot invent verification')
        report['input_sha256'] = hashes
        report['binary_sha256'] = {key: digest(getattr(args, key)) for key in ['reference', 'model', 'soundcheck']}
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 executable not found')
        z3 = str(Path(z3).resolve())
        artifacts = args.output.parent/'artifacts'
        prepared = {}
        original_decisions = {}
        with tempfile.TemporaryDirectory(prefix='soundcheck-preparation-z3-') as tools:
            Path(tools, 'z3').symlink_to(z3)
            environment = dict(os.environ, PATH=tools + os.pathsep + os.environ.get('PATH', ''))
            for name, expected in sorted(cases.items()):
                original = originals[name]
                folder = artifacts/name
                folder.mkdir(parents=True, exist_ok=True)
                entry = {'expected': expected, 'original_sha256': hashes[str(original)]}
                report['preparation_cases'][name] = entry
                upstream = execute([args.reference, original, args.requests],
                                   folder/'original-reference.json', environment)
                source_decisions = decisions(upstream, requests, 'reference', allow_unsupported=True)
                require((source_decisions is not None) == expected['reference_valid'],
                        f'Original reference validity differs: {name}')
                original_decisions[name] = source_decisions
                entry['original_reference_valid'] = source_decisions is not None
                with tempfile.TemporaryDirectory(prefix='receipt-', dir=folder) as temporary:
                    receipt_path = Path(temporary)/'receipt.json'
                    output = execute([args.soundcheck, 'rbac', 'prepare', original, '--receipt', receipt_path],
                                     folder/'prepare.json', environment, json_output=False)
                    if expected['expected_preparation'] == 'rejected':
                        require(output['returncode'] == 2 and output['stdout'] == '' and not receipt_path.exists(),
                                f'Rejected preparation produced output/receipt: {name}')
                        entry['preparation'] = 'rejected'
                        report['rejected_preparations'] += 1
                        continue
                    require(output['returncode'] == 0 and receipt_path.is_file(),
                            f'Preparation failed: {name}')
                    source = original.read_bytes()
                    normalized = output['stdout'].encode('utf-8')
                    receipt = read_json(receipt_path)
                    validate_receipt(receipt, source, normalized, expected['removed_fields'])
                    (folder/'receipt.json').write_bytes(receipt_path.read_bytes())
                target = folder/'prepared.json'
                target.write_bytes(normalized)
                prepared[name] = target
                entry.update(preparation='prepared', prepared_sha256=digest(target),
                             removed_fields=expected['removed_fields'])
                comparison = execute([args.reference, '--compare-policies', original, target],
                                     folder/'typed-policy-comparison.json', environment)
                entry['typed_policy'] = validate_policy_comparison(comparison, source, normalized)
                report['typed_policy_comparisons'] += 1
                report['accepted_preparations'] += 1

            require(args.baseline in prepared, 'The normalization baseline was not prepared')

            def replay(name, request, folder, label):
                request_file = folder/(label + '-request.json')
                save(request_file, [request])
                original = execute([args.reference, originals[name], request_file],
                                   folder/(label + '-original-reference.json'), environment)
                normalized = execute([args.reference, prepared[name], request_file],
                                     folder/(label + '-prepared-reference.json'), environment)
                model = execute([args.model, prepared[name], args.contract, request_file],
                                folder/(label + '-model.json'), environment)
                before = decisions(original, [request], 'reference')
                after = decisions(normalized, [request], 'reference')
                concrete = decisions(model, [request], 'model')
                symbolic = smt_decisions(model, [request], folder, label, z3, environment)
                require(before == after == concrete == symbolic, 'Prepared/original witness replay mismatch')
                report['upstream_witness_calls'] += 2
                return before['witness']

            for name, target in sorted(prepared.items()):
                expected = cases[name]
                folder = artifacts/name
                entry = report['preparation_cases'][name]
                upstream = execute([args.reference, target, args.requests], folder/'prepared-reference.json', environment)
                model = execute([args.model, target, args.contract, args.requests], folder/'matrix-model.json', environment)
                normalized = decisions(upstream, requests, 'reference')
                concrete = decisions(model, requests, 'model')
                symbolic = smt_decisions(model, requests, folder, 'matrix', z3, environment)
                require(original_decisions[name] == normalized == concrete == symbolic,
                        f'Preparation changed matrix decisions: {name}')
                entry['matrix_comparisons'] = len(requests)
                report['preparation_matrix_comparisons'] += len(requests)
                verified = execute([args.soundcheck, 'rbac', 'verify', target, '--contract', args.contract, '--format', 'json'],
                                   folder/'verify.json', environment)
                result = validate_report(verified, contract, expected['expected_contract'])
                entry['contract'] = result['result']
                if result['result'] == 'violated':
                    request = witness_request(result, identities)
                    clause = [x for x in contract['clauses'] if x['name'] == result.get('clause', {}).get('name')]
                    require(len(clause) == 1 and scope_matches(clause[0], request)
                            and result['clause'].get('kind') == clause[0]['kind'], 'Witness outside frozen clause')
                    wanted = 'NoOpinion' if clause[0]['kind'] == 'must_allow' else 'Allow'
                    require(replay(name, request, folder, 'verify-witness') == wanted,
                            'Original/prepared witness does not defeat the contract')
                    report['contract_witness_replays'] += 1
                preservation = expected['expected_preservation']
                if preservation is not None:
                    require(result['result'] == 'proved', 'Preservation fixture must reach comparison')
                    compared = execute([args.soundcheck, 'rbac', 'compare', prepared[args.baseline], target,
                                        '--contract', args.contract, '--format', 'json'], folder/'compare.json', environment)
                    result = validate_report(compared, contract, 'proved' if preservation == 'preserved' else 'violated')
                    entry['preservation'] = preservation
                    if result['result'] == 'violated':
                        require(result.get('property') == 'rbac-repair-preservation'
                                and result.get('clause', {}).get('kind') == 'must_preserve',
                                'Expected preservation witness')
                        request = witness_request(result, identities)
                        require(not any(scope_matches(scope, request) for scope in contract['change_scope']),
                                'Preservation witness lies inside approved changes')
                        before = replay(args.baseline, request, folder, 'preservation-before')
                        after = replay(name, request, folder, 'preservation-after')
                        require(before != after, 'No original/prepared preservation difference')
                        report['preservation_witness_replays'] += 2
                save(args.output, report)
                print(f'{name}: prepared, {entry["contract"]}', flush=True)

            controls = [('drop-binding', '01-export-unsafe'),
                        ('widen-resource-names', '07-export-named-secret-leak'),
                        ('change-subject', '01-export-unsafe'),
                        ('change-annotation', '01-export-unsafe'),
                        ('add-unobserved-verb', '03-export-valid-repair')]
            for control, name in controls:
                folder = artifacts/'corruption-controls'/control
                corrupted = folder/'corrupted.json'
                save(corrupted, mutate(read_json(prepared[name]), control))
                comparison = execute([args.reference, '--compare-policies', originals[name], corrupted],
                                     folder/'typed-policy-comparison.json', environment)
                validate_policy_comparison(comparison, originals[name].read_bytes(), corrupted.read_bytes(), equal=False)
                try:
                    validate_transformation(originals[name].read_bytes(), corrupted.read_bytes(), cases[name]['removed_fields'])
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError('Corrupted normalization passed the independent exact-transformation check')
                report['corruption_controls'][control] = {'rejected': True}
                if control == 'add-unobserved-verb':
                    upstream = execute([args.reference, corrupted, args.requests], folder/'matrix-reference.json', environment)
                    require(decisions(upstream, requests, 'reference') == original_decisions[name],
                            'Unobserved-verb control should evade the named-get matrix')
                    report['corruption_controls'][control]['matrix_would_match'] = True

        require(all(digest(Path(path)) == value for path, value in hashes.items()), 'Original inputs changed during preparation')
        require(all(digest(getattr(args, key)) == value for key, value in report['binary_sha256'].items()),
                'Reference/verifier binaries changed during preparation')
        require(all(digest(target) == report['preparation_cases'][name]['prepared_sha256']
                    for name, target in prepared.items()), 'Prepared inputs changed after checking')
        report['inputs_unchanged'] = True
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, StopIteration) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print({key: report[key] for key in ['complete', 'accepted_preparations', 'rejected_preparations',
                                      'preparation_matrix_comparisons', 'contract_witness_replays',
                                      'preservation_witness_replays', 'failures']})
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
