#!/usr/bin/env python3
"""Synthetic resource-request coexistence checks against Kubernetes v1.34.0.

URL authorization is used only as a native positive/control experiment. It is
never part of the connector's requests, contracts, or preservation assertion.
"""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, EXIT_CODES, decisions, digest, execute, module_provenance,
                 read_json, require, save, smt_decisions, strict_json)
from run_preparation import byte_hash, validate_policy_comparison, validate_receipt
from run_read_access import scope_matches
from run_write_access import normalize_contract, validate_contract, validate_request, witness_request

PROFILE = 'kubernetes-rbac-v1.34-read-write-v3'
API = 'rbac.authorization.k8s.io'
VERBS = ['get', 'list', 'watch', 'update', 'patch', 'delete']
READS = ['list', 'watch']
HERE = CORPUS/'nonresource'
FIXTURE36 = CORPUS/'preparation/fixtures/36-nonresource-rule-control.json'


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)+'\n').encode()


def url_rule(urls=None):
    return dict(verbs=['get'], nonResourceURLs=['/healthz'] if urls is None else urls)


def resource_rule(verb='get'):
    return dict(verbs=[verb], apiGroups=[''], resources=['configmaps'], resourceNames=['settings'])


def snapshot(rules, binding='ClusterRoleBinding', role='ClusterRole', bound=True):
    metadata = dict(name='coexistence')
    if role == 'Role':
        metadata['namespace'] = 'team-a'
    items = [dict(apiVersion=API+'/v1', kind=role, metadata=metadata, rules=rules)]
    if bound:
        metadata = dict(name='coexistence')
        if binding == 'RoleBinding':
            metadata['namespace'] = 'team-a'
        items.append(dict(apiVersion=API+'/v1', kind=binding, metadata=metadata,
            roleRef=dict(apiGroup=API, kind=role, name='coexistence'),
            subjects=[dict(kind='User', apiGroup=API, name='app')]))
    return dict(apiVersion='v1', kind='List', items=items)


def cases():
    """Fixed synthetic policies and expectations, independent of analyzer output."""
    values = []

    def add(name, rules, mode='none', binding='ClusterRoleBinding', role='ClusterRole'):
        verdict, failed = ('violated', 'required-config') if mode == 'none' else (
            ('violated', 'secrets-not-granted') if mode == 'wildcard' else ('proved', None))
        values.append(dict(id=name, snapshot=snapshot(rules, binding, role), mode=mode,
                           binding=binding, role=role, verdict=verdict, failed=failed))

    add('url-only-cluster-binding', [url_rule()])
    add('url-only-role-binding', [url_rule()], binding='RoleBinding')
    add('url-empty-string', [url_rule([''])])
    add('url-empty-verb', [dict(verbs=[''], nonResourceURLs=['/healthz'])])
    add('url-strings-and-verbs', [dict(verbs=['', 'GET', 'custom', '*'], nonResourceURLs=[
        '', '*', '/*', '/api*', '/foo**', '/foo*bar', 'relative', '/a?b', '/a#b', '/healthz'])])
    add('url-empty-resource-fields', [dict(url_rule(), apiGroups=[], resources=[], resourceNames=[])])
    add('url-null-resource-fields', [dict(url_rule(), apiGroups=None, resources=None, resourceNames=None)])
    separate = [url_rule(), resource_rule(), dict(verbs=[''], nonResourceURLs=['*']), resource_rule('patch')]
    add('separate-cluster-binding', copy.deepcopy(separate), 'separate')
    add('separate-role-binding', copy.deepcopy(separate), 'separate', 'RoleBinding')
    for label, urls in [('empty', []), ('null', None), ('absent', 'absent')]:
        rule = dict(verbs=['*'], apiGroups=['*'], resources=['*'])
        if label != 'absent':
            rule['nonResourceURLs'] = urls
        add('wildcard-'+label+'-cluster', [rule], 'wildcard')
        if label != 'absent':
            add('wildcard-'+label+'-role', [copy.deepcopy(rule)], 'wildcard', 'RoleBinding', 'Role')
    add('separate-resource-wildcard', [url_rule(), dict(verbs=['*'], apiGroups=[''], resources=['*'])], 'wildcard')
    return values


def rejected_cases():
    values = []

    def add(name, rules, role='ClusterRole', bound=True):
        binding = 'RoleBinding' if role == 'Role' else 'ClusterRoleBinding'
        values.append(dict(id=name, snapshot=snapshot(rules, binding, role, bound)))

    for key, content in [('apiGroups', ['']), ('resources', ['*']), ('resourceNames', ['']),
                         ('resourceNames', ['settings'])]:
        add('mixed-'+key+('-empty-string' if content == [''] else '-value'), [dict(url_rule(), **{key: content})])
    add('mixed-all-fields', [dict(resource_rule(), nonResourceURLs=['*'])])
    add('role-url', [url_rule()], role='Role')
    add('unbound-role-url', [url_rule()], role='Role', bound=False)
    add('unbound-mixed-rule', [dict(resource_rule(), nonResourceURLs=['/healthz'])], bound=False)
    for label, value in [('absent', 'absent'), ('null', None), ('empty', [])]:
        rule = url_rule()
        if label == 'absent':
            del rule['verbs']
        else:
            rule['verbs'] = value
        add('url-verbs-'+label, [rule])
        empty = dict(verbs=['get'])
        if label != 'absent':
            empty['nonResourceURLs'] = value
        add('empty-url-no-resources-'+label, [empty])
    for label, value in [('string', '/healthz'), ('number-element', [7]), ('object-element', [{}]), ('boolean', True)]:
        add('url-type-'+label, [dict(url_rule(), nonResourceURLs=value)])
    for key in ['verbs', 'apiGroups', 'resources', 'resourceNames']:
        add('url-other-field-type-'+key, [dict(url_rule(), **{key: '/not-an-array'})])
    return values


def requests_for(contract, fixture=False):
    values = []
    namespaces = ['frontend', 'ops', 'payments', 'unseen'] if fixture else ['team-a', 'team-b', 'unseen']
    identities = validate_contract(contract)
    for user, groups in identities.items():
        for verb in VERBS:
            for namespace in namespaces + ([''] if verb in READS else []):
                for resource in ['configmaps', 'secrets']:
                    for name in ['settings', 'other'] + ([''] if verb in READS else []):
                        request = dict(id=str(len(values)), username=user, groups=groups, verb=verb,
                            apiGroup='', resource=resource, namespace=namespace, name=name,
                            resourceRequest=True, subresource='')
                        validate_request(request, identities)
                        values.append(request)
    return values


def expected_grants(case, request):
    """Hand-written fixture expectations; deliberately never inspect rule content."""
    if case['mode'] == 'fixture36':
        if request['verb'] != 'get':
            return []
        who, ns, kind = request['username'], request['namespace'], request['resource']
        if who == 'system:serviceaccount:frontend:frontend-sa' and ns == 'frontend' and kind == 'configmaps':
            return ['RoleBinding/frontend/frontend-config -> ClusterRole/config-reader/rules/0']
        if who == 'system:serviceaccount:frontend:frontend-sa' and ns == 'payments' and kind == 'secrets':
            return ['RoleBinding/payments/frontend-extra -> ClusterRole/secret-reader/rules/0']
        if who == 'ops-auditor' and ns == 'ops' and kind == 'configmaps':
            return ['RoleBinding/ops/ops-config -> ClusterRole/config-reader/rules/0']
        return []
    if request['username'] != 'app' or case['mode'] == 'none':
        return []
    if case['binding'] == 'RoleBinding' and request['namespace'] != 'team-a':
        return []
    if case['mode'] == 'separate':
        if request['resource'] != 'configmaps' or request['name'] != 'settings' or request['verb'] not in ['get', 'patch']:
            return []
        index = 1 if request['verb'] == 'get' else 3
    else:
        require(case['mode'] == 'wildcard', 'Unknown independent expectation mode')
        index = 1 if case['id'] == 'separate-resource-wildcard' else 0
    binding = case['binding'] + ('/team-a' if case['binding'] == 'RoleBinding' else '') + '/coexistence'
    role = case['role'] + ('/team-a' if case['role'] == 'Role' else '') + '/coexistence'
    return [f'{binding} -> {role}/rules/{index}']


def checked_decisions(execution, requests, source, allow_unsupported=False):
    data = execution.get('data')
    require(isinstance(data, dict), 'Missing decision response object')
    if source == 'reference':
        require(set(data) == {'valid', 'validation_errors', 'decisions'}, 'Native decision response shape')
        keys = {'id', 'decision', 'reason', 'error'}
    else:
        keys = {'id', 'decision', 'grants'}
        expected = {'status', 'decisions', 'reason'} if data.get('status') == 'unknown' else {'status', 'decisions', 'matrix_smt'}
        require(set(data) == expected, 'Connector decision response shape')
        if data.get('status') == 'supported':
            require(isinstance(data['matrix_smt'], str) and data['matrix_smt'], 'Missing production SMT matrix')
    require(isinstance(data.get('decisions'), list), 'Missing decision array')
    for row in data['decisions']:
        require(isinstance(row, dict) and set(row) == keys, 'Decision row shape')
    return decisions(execution, requests, source, allow_unsupported=allow_unsupported)


def audit_model_grants(model, requests, case):
    checked_decisions(model, requests, 'model')
    by_id = {request['id']: request for request in requests}
    for row in model['data']['decisions']:
        require(row['grants'] == expected_grants(case, by_id[row['id']]), 'Wrong binding/role/original rule-index trace')


def audit_report(execution, contract, expected, case=None, preservation=False):
    value = execution.get('data')
    keys = {'schema_version', 'result', 'property', 'assurance', 'frozen_spec', 'clause', 'counterexample'}
    if expected == 'unknown':
        keys.add('reason')
    require(isinstance(value, dict) and set(value) == keys, 'CLI report shape')
    require(type(value['schema_version']) is int and value['schema_version'] == 10
            and value['result'] == expected and execution['returncode'] == EXIT_CODES[expected], 'CLI verdict/schema/exit')
    require(value['property'] == ('rbac-repair-preservation' if preservation else contract['kind']), 'Wrong report property')
    frozen = value['frozen_spec']
    require(isinstance(frozen, dict) and set(frozen) == {'schema_version', 'kind', 'canonical'}
            and type(frozen['schema_version']) is int and frozen['schema_version'] == 3
            and frozen['kind'] == contract['kind'] and isinstance(frozen['canonical'], str), 'Frozen identity shape')
    require(json.dumps(normalize_contract(strict_json(frozen['canonical'])), sort_keys=True)
            == json.dumps(normalize_contract(contract), sort_keys=True), 'Reported frozen contract changed')
    assurance = value['assurance']
    require(isinstance(assurance, dict) and set(assurance) == {'profile', 'status', 'findings'}
            and assurance['profile'] == PROFILE and isinstance(assurance['findings'], list), 'Assurance shape/profile')
    if expected == 'unknown':
        require(assurance['status'] == 'unsupported' and assurance['findings']
                and isinstance(value['reason'], str) and value['reason'], 'Unknown must explain unsupported input')
        for finding in assurance['findings']:
            require(isinstance(finding, dict) and set(finding) == {'code', 'service', 'route', 'detail'}
                    and finding['code'] == 'unsupported-rbac-input' and finding['service'] is None
                    and finding['route'] is None and isinstance(finding['detail'], str) and finding['detail'], 'Unsupported finding shape')
    else:
        require(assurance['status'] == 'within_profile' and assurance['findings'] == [], 'Supported assurance changed')
    if expected != 'violated':
        require(value['counterexample'] is None and value['clause'] is None, 'Unexpected witness/clause')
        return None
    require(case is not None and not preservation, 'Unexpected preservation violation')
    selected = value['clause']
    require(isinstance(selected, dict) and set(selected) == {'name', 'kind', 'description'}
            and isinstance(selected['description'], str) and selected['description'], 'Clause response shape')
    clauses = [c for c in contract['clauses'] if c['name'] == selected['name']]
    require(len(clauses) == 1 and selected['name'] == case['failed'] and selected['kind'] == clauses[0]['kind'], 'Wrong ordered failing clause')
    witness = value['counterexample']
    require(isinstance(witness, dict) and set(witness) == {'principal', 'action', 'path', 'host', 'scheme', 'sni',
        'headers', 'source_ip', 'route', 'service', 'shadowed_route', 'shadowed_service', 'object_request',
        'identity_groups', 'granting_rules'}, 'Counterexample shape')
    require(all(witness[k] == '' for k in ['path', 'host', 'scheme', 'sni'])
            and all(witness[k] is None for k in ['route', 'service', 'shadowed_route', 'shadowed_service'])
            and witness['headers'] == [] and witness['source_ip'] == '0.0.0.0', 'Unexpected non-resource witness coordinates')
    request = witness_request(value, validate_contract(contract))
    require(scope_matches(clauses[0], request), 'Counterexample outside the reported frozen clause')
    grants = expected_grants(case, request)
    require(witness['granting_rules'] == grants and bool(grants) == (selected['kind'] == 'must_not_grant'),
            'Counterexample decision/grant indices disagree with independent fixture expectation')
    return request


def audit_comparison(execution, original, prepared, equal, object_count):
    value = validate_policy_comparison(execution, original, prepared, equal=equal)
    require(value['original_objects'] == value['prepared_objects'] == object_count, 'Typed-policy object inventory changed')
    if not equal:
        require(value['differences'] == ['changed: ClusterRole\x00\x00coexistence'], 'Unexpected native policy difference')


def planned_inputs():
    result = {case['id']+'.json': encoded(case['snapshot']) for case in cases()+rejected_cases()}
    require(len(result) == len(cases())+len(rejected_cases()), 'Duplicate case name')
    result['contract.json'] = (HERE/'contract.json').read_bytes()
    result['fixture36.json'] = FIXTURE36.read_bytes()
    return result


def audit_input_pins(inputs, pins):
    require(isinstance(pins, dict) and set(pins) == set(inputs), 'Synthetic input pin inventory mismatch')
    for name, data in inputs.items():
        require(isinstance(pins[name], dict) and set(pins[name]) == {'sha256', 'bytes'}
                and type(pins[name]['bytes']) is int
                and pins[name] == dict(sha256=byte_hash(data), bytes=len(data)), 'Fixed input changed: '+name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default=os.environ.get('Z3', 'z3'))
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    report = dict(complete=False, profile=PROFILE, cases={}, failures=[], input_sha256={}, binary_sha256={},
        matrix_comparisons=0, typed_policy_comparisons=0, contract_witness_replays=0,
        rejected_controls=0, native_url_checks=0, model_boundary_controls=0,
        whole_policy_difference_controls=0, resource_preservation_checks=0,
        limits=['Synthetic offline snapshots and fixed trusted identity groups; no installed cluster claims.',
                'Only core ConfigMaps/Secrets resource requests are modeled; URL decisions are native controls only.',
                'Resource preservation does not assert preservation of nonresource URL permissions.',
                'Finite conformance checks are not a universal proof of parser or encoder correctness.'])
    artifacts = args.output.parent/'artifacts'
    try:
        inputs = planned_inputs()
        audit_input_pins(inputs, read_json(HERE/'inputs.json'))
        contract = strict_json(inputs['contract.json'])
        validate_contract(contract)
        require(contract['change_scope'] == [], 'URL-edit comparison must preserve the entire modeled resource domain')
        report['reference'] = module_provenance(args.module_metadata)
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 executable required')
        for path in [args.reference, args.model, args.soundcheck, Path(z3)]:
            report['binary_sha256'][str(path)] = digest(path)
        for path in [Path(__file__).resolve(), HERE/'contract.json', HERE/'inputs.json', FIXTURE36]:
            report['input_sha256'][str(path)] = digest(path)
        artifacts.mkdir(parents=True, exist_ok=True)
        contract_path = artifacts/'contract.json'
        contract_path.write_bytes(inputs['contract.json'])
        planned = cases()+[dict(id='fixture36', mode='fixture36', verdict='violated', failed='required-config')]
        for case in planned+rejected_cases():
            folder = artifacts/case['id']
            folder.mkdir(parents=True, exist_ok=True)
            path = folder/'original.json'
            path.write_bytes(inputs[case['id']+'.json'])
            report['input_sha256'][str(path)] = digest(path)
        report['input_sha256'][str(contract_path)] = digest(contract_path)
        save(args.output, report)
        with tempfile.TemporaryDirectory(prefix='soundcheck-nonresource-') as temporary:
            Path(temporary, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=temporary+os.pathsep+os.environ.get('PATH', ''))
            accepted = {}
            for case in planned:
                name = case['id']
                folder, original = artifacts/name, artifacts/name/'original.json'
                requests = requests_for(contract, fixture=name == 'fixture36')
                requests_path = folder/'requests.json'
                save(requests_path, requests)
                report['input_sha256'][str(requests_path)] = digest(requests_path)
                expected = {r['id']: 'Allow' if expected_grants(case, r) else 'NoOpinion' for r in requests}
                before = execute([args.reference, original, requests_path], folder/'original-reference.json', environment)
                require(checked_decisions(before, requests, 'reference') == expected, 'Native decisions differ from fixed expectations: '+name)
                receipt_path = Path(temporary, name+'-receipt.json')
                prepared = execute([args.soundcheck, 'rbac', 'prepare', original, '--receipt', receipt_path],
                    folder/'prepare.json', environment, json_output=False)
                object_count = len(strict_json(inputs[name+'.json'])['items'])
                expected_summary = f'Prepared {object_count} RBAC objects; removed 0 metadata fields. No verification or completeness claim.\n'
                require(prepared['returncode'] == 0 and receipt_path.is_file()
                        and prepared['stderr'] == expected_summary, 'Preparation failed: '+name)
                output = prepared['stdout'].encode()
                receipt = read_json(receipt_path)
                validate_receipt(receipt, original.read_bytes(), output, [])
                save(folder/'receipt.json', receipt)
                target = folder/'prepared.json'
                target.write_bytes(output)
                report['input_sha256'][str(target)] = digest(target)
                # The AST audit above retains URL literals, order, empty/null
                # arrays and every field. The independent typed comparison
                # additionally binds both policies to native defaulting/types.
                compared = execute([args.reference, '--compare-policies', original, target], folder/'typed-policy.json', environment)
                audit_comparison(compared, original.read_bytes(), output, True, object_count)
                report['typed_policy_comparisons'] += 1
                after = execute([args.reference, target, requests_path], folder/'prepared-reference.json', environment)
                model = execute([args.model, target, contract_path, requests_path], folder/'model.json', environment)
                require(checked_decisions(after, requests, 'reference') == expected
                        == checked_decisions(model, requests, 'model')
                        == smt_decisions(model, requests, folder, 'matrix', z3, environment), 'Native/prepared/connector/SMT disagreement: '+name)
                audit_model_grants(model, requests, case)
                report['matrix_comparisons'] += len(requests)
                verified = execute([args.soundcheck, 'rbac', 'verify', target, '--contract', contract_path, '--format', 'json'],
                    folder/'verify.json', environment)
                witness = audit_report(verified, contract, case['verdict'], case)
                if witness is not None:
                    witness_path = folder/'witness.json'
                    save(witness_path, [witness])
                    report['input_sha256'][str(witness_path)] = digest(witness_path)
                    replay = execute([args.reference, original, witness_path], folder/'witness-reference.json', environment)
                    desired = 'Allow' if case['failed'] == 'secrets-not-granted' else 'NoOpinion'
                    require(checked_decisions(replay, [witness], 'reference') == {'witness': desired}, 'Wrong native witness decision')
                    report['contract_witness_replays'] += 1
                report['cases'][name] = dict(result=case['verdict'], failed_clause=case['failed'],
                    requests=len(requests), original_sha256=digest(original), prepared_sha256=digest(target))
                accepted[name] = (case, target, requests, requests_path, expected)
                save(args.output, report)
                print(name+': '+case['verdict'], flush=True)

            # Native URL permissions are observable, while the connector stays
            # explicitly outside that domain. Remove path when probing the
            # model so the resourceRequest boundary is actually exercised.
            url_requests = [dict(id='url-'+name, username='app', groups=[], verb='get', apiGroup='', resource='',
                namespace='', name='', subresource='', resourceRequest=False, path=path)
                for name, path in [('health', '/healthz'), ('other', '/readyz')]]
            url_path = artifacts/'url-requests.json'
            save(url_path, url_requests)
            report['input_sha256'][str(url_path)] = digest(url_path)
            for name, desired in [('url-only-cluster-binding', ['Allow', 'NoOpinion']),
                                  ('url-only-role-binding', ['NoOpinion', 'NoOpinion']),
                                  ('separate-cluster-binding', ['Allow', 'NoOpinion'])]:
                _, target, _, _, _ = accepted[name]
                result = execute([args.reference, target, url_path], artifacts/name/'native-url.json', environment)
                require(checked_decisions(result, url_requests, 'reference') ==
                        {r['id']: d for r, d in zip(url_requests, desired)}, 'Native nonresource positive/binding control failed')
                report['native_url_checks'] += len(url_requests)
                outside = [{k: v for k, v in r.items() if k != 'path'} for r in url_requests]
                outside_path = artifacts/name/'outside-resource-domain.json'
                save(outside_path, outside)
                report['input_sha256'][str(outside_path)] = digest(outside_path)
                result = execute([args.model, target, contract_path, outside_path], artifacts/name/'model-url-boundary.json', environment)
                require(checked_decisions(result, outside, 'model', allow_unsupported=True) is None
                        and 'resourceRequest must be true' in result['data']['reason'], 'Model acquired URL authorization or rejected the wrong boundary')
                report['model_boundary_controls'] += 1

            case, baseline, requests, requests_path, expected = accepted['separate-cluster-binding']
            for mutation in ['alter-url', 'drop-url-rule']:
                folder = artifacts/mutation
                altered = strict_json(baseline.read_bytes())
                if mutation == 'alter-url':
                    altered['items'][0]['rules'][0]['nonResourceURLs'] = ['/readyz']
                else:
                    del altered['items'][0]['rules'][0]
                target = folder/'candidate.json'
                save(target, altered)
                report['input_sha256'][str(target)] = digest(target)
                compared = execute([args.reference, '--compare-policies', baseline, target], folder/'typed-policy.json', environment)
                audit_comparison(compared, baseline.read_bytes(), target.read_bytes(), False, 2)
                report['whole_policy_difference_controls'] += 1
                native = execute([args.reference, target, requests_path], folder/'resource-reference.json', environment)
                require(checked_decisions(native, requests, 'reference') == expected, 'URL-only policy edit changed resource decisions')
                native = execute([args.reference, target, url_path], folder/'url-reference.json', environment)
                desired = {'url-health': 'NoOpinion', 'url-other': 'Allow' if mutation == 'alter-url' else 'NoOpinion'}
                require(checked_decisions(native, url_requests, 'reference') == desired, 'Native URL change control did not change permissions')
                report['native_url_checks'] += len(url_requests)
                comparison = execute([args.soundcheck, 'rbac', 'compare', baseline, target, '--contract', contract_path, '--format', 'json'],
                    folder/'resource-preservation.json', environment)
                audit_report(comparison, contract, 'proved', preservation=True)
                report['resource_preservation_checks'] += 1

            probe = [requests_for(contract)[0]]
            probe_path = artifacts/'rejection-probe.json'
            save(probe_path, probe)
            report['input_sha256'][str(probe_path)] = digest(probe_path)
            for case in rejected_cases():
                name = case['id']
                folder, original = artifacts/name, artifacts/name/'original.json'
                native = execute([args.reference, original, probe_path], folder/'native-rejection.json', environment)
                require(checked_decisions(native, probe, 'reference', allow_unsupported=True) is None, 'Native validator accepted malformed fixture: '+name)
                model = execute([args.model, original, contract_path, probe_path], folder/'model-rejection.json', environment)
                require(checked_decisions(model, probe, 'model', allow_unsupported=True) is None, 'Connector accepted malformed fixture: '+name)
                receipt_path = Path(temporary, name+'-receipt.json')
                preparation = execute([args.soundcheck, 'rbac', 'prepare', original, '--receipt', receipt_path],
                    folder/'prepare-rejection.json', environment, json_output=False)
                require(preparation['returncode'] == 2 and preparation['stdout'] == '' and preparation['stderr']
                        and not receipt_path.exists(), 'Rejected preparation produced output or receipt: '+name)
                verified = execute([args.soundcheck, 'rbac', 'verify', original, '--contract', contract_path, '--format', 'json'],
                    folder/'verify-rejection.json', environment)
                audit_report(verified, contract, 'unknown')
                report['rejected_controls'] += 1
                report['cases'][name] = dict(result='unknown', native_valid=False, preparation='rejected')
            require(all(digest(Path(path)) == value for path, value in report['input_sha256'].items()), 'Input/source bytes changed during conformance')
            require(all(digest(Path(path)) == value for path, value in report['binary_sha256'].items()), 'Tool binary changed during conformance')
            audit_input_pins(planned_inputs(), read_json(HERE/'inputs.json'))
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print({key: report[key] for key in ['complete', 'matrix_comparisons', 'typed_policy_comparisons',
        'contract_witness_replays', 'rejected_controls', 'whole_policy_difference_controls', 'resource_preservation_checks', 'failures']})
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
