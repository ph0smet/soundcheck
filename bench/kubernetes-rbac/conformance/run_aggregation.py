#!/usr/bin/env python3
"""Synthetic aggregate snapshots checked against the production Kubernetes controller.

The independent expected rules and permissions are fixed before execution. A
reference-only sentinel seed forces actual controller updates; reaching that
expected state is a finite observation, not a liveness/convergence proof.
"""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, EXIT_CODES, digest, execute, module_provenance, read_json,
                 require, save, smt_decisions, strict_json)
from run_nonresource import checked_decisions
from run_preparation import byte_hash, validate_policy_comparison, validate_receipt
from run_read_access import scope_matches
from run_write_access import normalize_contract, validate_contract, validate_request, witness_request

HERE = CORPUS/'aggregation'
PROFILE = 'kubernetes-rbac-v1.34-read-write-v3'
API = 'rbac.authorization.k8s.io'
VERBS = ['get', 'list', 'watch', 'update', 'patch', 'delete']


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)+'\n').encode()


def rule(resource='configmaps', name='settings', verb='get', group=''):
    value = dict(verbs=[verb], apiGroups=[group], resources=[resource])
    if name is not None:
        value['resourceNames'] = [name]
    return value


def role(name, rules, labels=None, selectors=None):
    value = dict(apiVersion=API+'/v1', kind='ClusterRole', metadata=dict(name=name), rules=copy.deepcopy(rules))
    if labels is not None:
        value['metadata']['labels'] = labels
    if selectors is not None:
        value['aggregationRule'] = dict(clusterRoleSelectors=selectors)
    return value


def binding(name, role_name, namespace, username=None):
    value = dict(apiVersion=API+'/v1', kind='ClusterRoleBinding' if namespace is None else 'RoleBinding',
        metadata=dict(name=name), roleRef=dict(apiGroup=API, kind='ClusterRole', name=role_name),
        subjects=[dict(kind='Group' if username is None else 'User', apiGroup=API,
                       name='readers' if username is None else username)])
    if namespace is not None:
        value['metadata']['namespace'] = namespace
    return value


def contract():
    access = dict(subject='app', verb='get', namespace='team-a', resource='secrets', names=None)
    return dict(schema_version=3, kind='kubernetes-rbac-access',
        context=dict(schema_version=1, snapshot_complete=True, identities=[
            dict(username='app', groups=['readers']), dict(username='operator', groups=[])]),
        clauses=[dict(name='required-config', kind='must_allow', subject='app', verb='get',
                      namespace='team-a', resource='configmaps', names=['settings']),
                 dict(name='secrets-not-granted', kind='must_not_grant', **access)],
        change_scope=[access])


def cases():
    """Literal expected grants; no expectation is read from a verifier/native result."""
    result = []
    get, secret = rule(), rule('secrets', None)
    url, pods = dict(verbs=['get'], nonResourceURLs=['/healthz']), rule('pods', None)
    select = lambda key, value: dict(matchLabels={key: value})

    def add(name, roots, expected, *, mode='settings', indices=None, cluster=False, operator=True,
            accepted=True, native_valid=True, controller=True, failed=None):
        items = copy.deepcopy(roots) + [role('operator', [rule(name='status')]), binding('app', 'root', None if cluster else 'team-a')]
        if operator:
            items.append(binding('operator', 'operator', 'ops', 'operator'))
        verdict = 'unknown' if not accepted else ('violated' if failed else 'proved')
        result.append(dict(id=name, snapshot=dict(apiVersion='v1', kind='List', items=items),
            expected_rules=copy.deepcopy(expected), mode=mode,
            indices=indices or {'settings': [0]}, cluster=cluster, operator=operator,
            accepted=accepted, native_valid=native_valid, controller=controller,
            verdict=verdict, failed=failed))

    def basic(rules=None, leaf_rules=None, selectors=None):
        return [role('leaf', [get] if leaf_rules is None else leaf_rules, {'selected': 'yes'}),
                role('root', [get] if rules is None else rules,
                     selectors=[select('selected', 'yes')] if selectors is None else selectors)]

    add('match-labels', basic(), {'root': [get]})
    add('cluster-binding', basic(), {'root': [get]}, cluster=True)
    expressions = [dict(key='tier', operator='In', values=['reader']),
        dict(key='zone', operator='NotIn', values=['blocked']),
        dict(key='ready', operator='Exists'), dict(key='forbidden', operator='DoesNotExist')]
    add('all-expression-operators', [role('leaf', [get], {'app': 'demo', 'tier': 'reader', 'ready': ''}),
        role('excluded', [secret], {'app': 'demo', 'tier': 'reader', 'ready': '', 'zone': 'blocked'}),
        role('root', [get], selectors=[dict(matchLabels={'app': 'demo'}, matchExpressions=expressions)])], {'root': [get]})
    labels = {'app': 'demo', 'tier': 'reader', 'ready': '', 'zone': 'ok'}
    isolated = [role('good', [get], labels)]
    for name, key, replacement in [('wrong-tier', 'tier', 'writer'), ('missing-tier', 'tier', None),
        ('missing-ready', 'ready', None), ('present-forbidden', 'forbidden', 'yes'),
        ('wrong-app', 'app', 'other'), ('blocked-zone', 'zone', 'blocked')]:
        bad_labels = dict(labels)
        if replacement is None:
            del bad_labels[key]
        else:
            bad_labels[key] = replacement
        isolated.append(role(name, [secret], bad_labels))
    isolated.append(role('root', [get], selectors=[dict(matchLabels={'app': 'demo'}, matchExpressions=expressions)]))
    add('each-selector-requirement-excludes-secret', isolated, {'root': [get]})
    add('empty-label-value-needs-presence', [role('leaf', [get], {'optional': ''}),
        role('excluded', [secret]), role('root', [get], selectors=[select('optional', '')])], {'root': [get]})
    patch = rule(verb='patch')
    add('selector-union', [role('leaf-get', [get], {'get': 'yes'}), role('leaf-patch', [patch], {'patch': 'yes'}),
        role('root', [get, patch], selectors=[select('get', 'yes'), select('patch', 'yes')])],
        {'root': [get, patch]}, mode='get-patch', indices={'settings': [0], 'patch': [1]})
    nested = [role('leaf', [get, url, pods], {'leaf': 'yes'}),
        role('middle', [get, url, pods], {'middle': 'yes'}, [select('leaf', 'yes')]),
        role('root', [get, url, pods], {'middle': 'yes'}, [select('middle', 'yes')])]
    add('nested-full-rules-and-self-skip', nested, {'middle': [get, url, pods], 'root': [get, url, pods]})
    duplicated = dict(get, verbs=['get', 'get'], resourceNames=['settings', 'settings'])
    add('rule-order-and-duplicates', basic([url, duplicated, get], [get, url]), {'root': [get, url]},
        indices={'settings': [1, 2]})
    add('empty-selector-selects-all', [role('leaf', [get]), role('root', [get, rule(name='status')], selectors=[{}])],
        {'root': [get, rule(name='status')]}, mode='all-config', indices={'settings': [0], 'status': [1]})
    add('no-matches', basic([], selectors=[select('missing', 'yes')]), {'root': []}, mode='empty', failed='required-config')
    add('self-only', [role('root', [], {'self': 'yes'}, [select('self', 'yes')])],
        {'root': []}, mode='empty', failed='required-config')
    add('unbound-empty-aggregate', basic()+[role('unused', [], selectors=[select('missing', 'yes')])],
        {'root': [get], 'unused': []})
    null = basic()
    null[0]['aggregationRule'] = None
    add('null-aggregation-is-plain', null, {'root': [get]})
    add('unsafe-selected-secrets', basic([get, secret], [get, secret]), {'root': [get, secret]},
        mode='unsafe', indices={'settings': [0], 'secret': [1]}, failed='secrets-not-granted')
    add('operator-regression', basic(), {'root': [get]}, operator=False)

    add('stale-empty', basic([]), {'root': [get]}, mode='empty', accepted=False)
    add('stale-missing-secret', basic([get], [get, secret]), {'root': [get, secret]}, accepted=False)
    add('stale-extra-secret', basic([get, secret]), {'root': [get]}, mode='unsafe',
        indices={'settings': [0], 'secret': [1]}, accepted=False)
    add('stale-url', basic([get], [get, url]), {'root': [get, url]}, accepted=False)
    add('stale-other-resource', basic([get], [get, pods]), {'root': [get, pods]}, accepted=False)
    add('stale-other-api-group', basic([get], [get, rule(group='custom.example')]),
        {'root': [get, rule(group='custom.example')]}, accepted=False)
    add('stale-name', basic([get], [rule(name='different')]), {'root': [rule(name='different')]}, accepted=False)
    stale_nested = copy.deepcopy(nested)
    stale_nested[1]['rules'] = []
    add('stale-unbound-middle', stale_nested, {'middle': [get, url, pods], 'root': [get, url, pods]}, accepted=False)
    add('unbound-stale-aggregate', basic()+[role('unused', [secret], selectors=[select('missing', 'yes')])],
        {'root': [get], 'unused': []}, accepted=False)
    cycle = [role('root', [get], {'side': 'root'}, [select('side', 'middle')]),
             role('middle', [get], {'side': 'middle'}, [select('side', 'root')])]
    add('cycle-with-stale-seed', cycle, {}, accepted=False, controller=False)
    cycle[0]['rules'], cycle[1]['rules'] = [], []
    add('empty-cycle', cycle, {}, mode='empty', accepted=False, controller=False)
    for name, aggregation in [
        ('missing-selectors', {}), ('empty-selectors', {'clusterRoleSelectors': []}),
        ('unknown-operator', {'clusterRoleSelectors': [{'matchExpressions': [dict(key='tier', operator='Gt', values=['1'])]}]}),
        ('empty-in', {'clusterRoleSelectors': [{'matchExpressions': [dict(key='tier', operator='In', values=[])]}]}),
        ('exists-with-values', {'clusterRoleSelectors': [{'matchExpressions': [dict(key='tier', operator='Exists', values=['x'])]}]}),
        ('bad-selector-key', {'clusterRoleSelectors': [select('bad key', 'yes')]}),
        ('bad-selector-value', {'clusterRoleSelectors': [select('selected', 'bad value')]}),
        ('unknown-selector-field', {'clusterRoleSelectors': [{'unexpected': True}]}),
    ]:
        invalid = basic()
        invalid[1]['aggregationRule'] = aggregation
        add(name, invalid, {}, accepted=False, native_valid=False, controller=False)
    return result


def expected_grants(case, request):
    who, verb, ns, resource, name = (request[key] for key in ['username', 'verb', 'namespace', 'resource', 'name'])
    if who == 'operator':
        return ['RoleBinding/ops/operator -> ClusterRole/operator/rules/0'] if (
            case['operator'] and verb == 'get' and ns == 'ops' and resource == 'configmaps' and name == 'status') else []
    if who != 'app' or (not case['cluster'] and ns != 'team-a') or case['mode'] == 'empty':
        return []
    kind = None
    if resource == 'configmaps':
        if name == 'settings' and verb == 'get':
            kind = 'settings'
        elif name == 'settings' and verb == 'patch' and case['mode'] == 'get-patch':
            kind = 'patch'
        elif name == 'status' and verb == 'get' and case['mode'] == 'all-config':
            kind = 'status'
    elif resource == 'secrets' and verb == 'get' and case['mode'] == 'unsafe':
        kind = 'secret'
    if kind is None:
        return []
    binding = 'ClusterRoleBinding/app' if case['cluster'] else 'RoleBinding/team-a/app'
    return [f'{binding} -> ClusterRole/root/rules/{i}' for i in case['indices'][kind]]


def requests_for(frozen):
    identities = validate_contract(frozen)
    result = []
    for who, groups in identities.items():
        for verb in VERBS:
            for namespace in ['team-a', 'ops', 'unseen'] + ([''] if verb in ['list', 'watch'] else []):
                for resource in ['configmaps', 'secrets']:
                    for name in ['settings', 'status', 'other'] + ([''] if verb in ['list', 'watch'] else []):
                        request = dict(id=f'r{len(result)}', username=who, groups=groups, verb=verb,
                            apiGroup='', resource=resource, namespace=namespace, name=name,
                            resourceRequest=True, subresource='')
                        validate_request(request, identities)
                        result.append(request)
    return result


def rule_set(rules):
    fields = ['verbs', 'apiGroups', 'resources', 'resourceNames', 'nonResourceURLs']
    return sorted({json.dumps([sorted(set(rule.get(key) or [])) for key in fields]) for rule in rules or []})


def controller_projection(snapshot):
    require(isinstance(snapshot, dict) and snapshot.get('kind') == 'List' and snapshot.get('apiVersion') == 'v1'
            and isinstance(snapshot.get('items'), list), 'Controller snapshot shape')
    result = {}
    for item in snapshot['items']:
        require(isinstance(item, dict) and isinstance(item.get('metadata'), dict), 'Controller object shape')
        meta = item['metadata']
        key = (item.get('kind'), meta.get('namespace', ''), meta.get('name'))
        require(key not in result and isinstance(key[2], str), 'Controller object identities')
        # Typed output may add zero-valued ObjectMeta bookkeeping. All policy
        # fields, labels, annotations and object identities remain compared.
        value = {k: v for k, v in item.items() if k != 'metadata'}
        value['metadata'] = dict(name=meta['name'], namespace=meta.get('namespace', ''),
            labels=meta.get('labels') or {}, annotations=meta.get('annotations') or {})
        if item['kind'] in ['Role', 'ClusterRole']:
            value['rules'] = rule_set(item.get('rules'))
            value['aggregationRule'] = item.get('aggregationRule')
        result[key] = value
    return result


def audit_controller(execution, case, source, expected_bytes):
    data = execution.get('data')
    require(isinstance(data, dict) and set(data) == {'schema_version', 'kind', 'source_sha256', 'expected_sha256',
        'valid', 'validation_errors', 'controller_executed', 'expected_reached', 'aggregate_roles', 'updates',
        'seeded_snapshot', 'snapshot', 'reconciliations'}, 'Controller response shape')
    require(execution['returncode'] == 0 and type(data['schema_version']) is int and data['schema_version'] == 1
            and data['kind'] == 'upstream_aggregation_controller_reference' and data['valid'] is True
            and data['validation_errors'] == [] and data['controller_executed'] is True
            and data['expected_reached'] is True, 'Controller execution did not reach expected state')
    require(data['source_sha256'] == byte_hash(source) and data['expected_sha256'] == byte_hash(expected_bytes),
            'Controller input identity mismatch')
    names = sorted(case['expected_rules'])
    require(data['aggregate_roles'] == names and names, 'Controller aggregate inventory mismatch')
    require(isinstance(data['updates'], list) and data['updates'], 'No production controller updates')
    updated = set()
    require(isinstance(data['reconciliations'], list) and data['reconciliations']
            and all(name in names for name in data['reconciliations']), 'Missing controller reconciliation trace')
    for index, update in enumerate(data['updates']):
        require(isinstance(update, dict) and set(update) == {'name', 'rules', 'resource_version'} and update['name'] in names
                and update['resource_version'] == str(index+1)
                and (update['rules'] is None or isinstance(update['rules'], list)), 'Controller update shape')
        updated.add(update['name'])
    require(updated == set(names), 'An aggregate bypassed controller execution')
    expected = controller_projection(case['snapshot'])
    seeded = copy.deepcopy(expected)
    sentinel = rule('sentinel', None, group='soundcheck-reference.invalid')
    for name in names:
        key = ('ClusterRole', '', name)
        expected[key]['rules'] = rule_set(case['expected_rules'][name])
        seeded[key]['rules'] = rule_set([sentinel])
    require(controller_projection(data['seeded_snapshot']) == seeded, 'Reference seed changed more than aggregate rules')
    require(controller_projection(data['snapshot']) == expected, 'Native output differs from independent expected full policy')
    return data['snapshot']


def audit_report(execution, frozen, expected, case=None, preservation=False):
    value = execution.get('data')
    keys = {'schema_version', 'result', 'property', 'assurance', 'frozen_spec', 'clause', 'counterexample'}
    if expected == 'unknown':
        keys.add('reason')
    require(isinstance(value, dict) and set(value) == keys and type(value['schema_version']) is int
            and value['schema_version'] == 10 and value['result'] == expected
            and execution['returncode'] == EXIT_CODES[expected], 'Report shape/verdict/schema/exit')
    require(value['property'] == ('rbac-repair-preservation' if preservation else frozen['kind']), 'Report property')
    spec = value['frozen_spec']
    require(isinstance(spec, dict) and set(spec) == {'schema_version', 'kind', 'canonical'}
            and type(spec['schema_version']) is int and spec['schema_version'] == 3
            and spec['kind'] == frozen['kind'] and isinstance(spec['canonical'], str)
            and normalize_contract(strict_json(spec['canonical'])) == normalize_contract(frozen), 'Frozen contract changed')
    assurance = value['assurance']
    require(isinstance(assurance, dict) and set(assurance) == {'profile', 'status', 'findings'}
            and assurance['profile'] == PROFILE, 'Wrong aggregate assurance profile')
    if expected == 'unknown':
        require(assurance['status'] == 'unsupported' and isinstance(assurance['findings'], list)
                and assurance['findings'] and isinstance(value['reason'], str) and value['reason'], 'Unsupported reason missing')
        for finding in assurance['findings']:
            require(isinstance(finding, dict) and set(finding) == {'code', 'service', 'route', 'detail'}
                    and finding['code'] == 'unsupported-rbac-input' and finding['service'] is None
                    and finding['route'] is None and isinstance(finding['detail'], str) and finding['detail'],
                    'Unsupported finding shape')
    else:
        require(assurance['status'] == 'within_profile' and assurance['findings'] == [], 'Supported assurance')
    if expected != 'violated':
        require(value['counterexample'] is None and value['clause'] is None, 'Unexpected witness or clause')
        return None
    raw = value['counterexample']
    require(isinstance(raw, dict) and set(raw) == {'principal', 'action', 'path', 'host', 'scheme', 'sni',
        'headers', 'source_ip', 'route', 'service', 'shadowed_route', 'shadowed_service', 'object_request',
        'identity_groups', 'granting_rules'}, 'Counterexample shape')
    require(all(raw[k] == '' for k in ['path', 'host', 'scheme', 'sni'])
            and all(raw[k] is None for k in ['route', 'service', 'shadowed_route', 'shadowed_service'])
            and raw['headers'] == [] and raw['source_ip'] == '0.0.0.0', 'Unexpected HTTP witness coordinates')
    witness = witness_request(value, validate_contract(frozen))
    if preservation:
        require(value['clause'] == dict(name='preservation-outside-change-scope', kind='must_preserve',
            description='"operator" get core configmaps "status" in namespace "ops" changed from Allow to NoOpinion outside the approved change scope'),
            'Wrong preservation clause')
        require(witness == dict(id='witness', username='operator', groups=[], verb='get', apiGroup='',
            resource='configmaps', namespace='ops', name='status', resourceRequest=True, subresource='')
            and raw['granting_rules'] == [] and not any(scope_matches(scope, witness) for scope in frozen['change_scope']),
                'Preservation witness inside approved changes')
    else:
        clause = value['clause']
        require(isinstance(clause, dict) and set(clause) == {'name', 'kind', 'description'}
                and clause['name'] == case['failed'] and isinstance(clause['description'], str) and clause['description'], 'Wrong ordered clause')
        selected = next(c for c in frozen['clauses'] if c['name'] == case['failed'])
        require(clause['kind'] == selected['kind'] and scope_matches(selected, witness), 'Witness outside frozen clause')
        grants = expected_grants(case, witness)
        require(value['counterexample']['granting_rules'] == grants
                and bool(grants) == (selected['kind'] == 'must_not_grant'), 'Witness/grant expectation mismatch')
    return witness


def planned_inputs():
    inputs = {'contract.json': encoded(contract())}
    for case in cases():
        inputs[case['id']+'.json'] = encoded(case['snapshot'])
        if case['controller']:
            inputs[case['id']+'-expected.json'] = encoded(case['expected_rules'])
    return inputs


def audit_pins(inputs, pins):
    require(isinstance(pins, dict) and set(pins) == set(inputs), 'Fixture pin inventory differs')
    for name, content in inputs.items():
        require(pins[name] == dict(sha256=byte_hash(content), bytes=len(content)), 'Fixture pin changed: '+name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args(argv)
    report = dict(complete=False, reference='Kubernetes v1.34.0 aggregation controller and RBAC authorizer',
        profile=PROFILE, cases={}, controller_cases=0, matrix_comparisons=0, rejected_controls=0,
        contract_witness_replays=0, preservation_witness_replays=0, typed_policy_comparisons=0,
        input_sha256={}, binary_sha256={}, failures=[])
    artifacts = args.output.parent/'artifacts'
    try:
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 required')
        report['module_provenance'] = module_provenance(args.module_metadata)
        inputs = planned_inputs()
        audit_pins(inputs, read_json(HERE/'inputs.json'))
        require((HERE/'contract.json').read_bytes() == inputs['contract.json'], 'Frozen contract bytes changed')
        for path in [args.reference, args.model, args.soundcheck, Path(z3)]:
            report['binary_sha256'][str(path)] = digest(path)
        for path in [Path(__file__).resolve(), HERE/'inputs.json', HERE/'contract.json']:
            report['input_sha256'][str(path)] = digest(path)
        for name, content in inputs.items():
            path = artifacts/'inputs'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            report['input_sha256'][str(path)] = digest(path)
        frozen = strict_json(inputs['contract.json'])
        contract_path = artifacts/'inputs/contract.json'
        requests = requests_for(frozen)
        request_path = artifacts/'requests.json'
        save(request_path, requests)
        report['input_sha256'][str(request_path)] = digest(request_path)
        save(args.output, report)
        with tempfile.TemporaryDirectory(prefix='soundcheck-aggregation-') as temporary:
            Path(temporary, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=temporary+os.pathsep+os.environ.get('PATH', ''))
            for case in cases():
                name = case['id']
                folder, original = artifacts/name, artifacts/'inputs'/(name+'.json')
                native = execute([args.reference, original, request_path], folder/'native.json', environment)
                actual = checked_decisions(native, requests, 'reference', allow_unsupported=not case['native_valid'])
                if case['native_valid']:
                    expected = {r['id']: 'Allow' if expected_grants(case, r) else 'NoOpinion' for r in requests}
                    require(actual == expected, 'Native original differs from literal decisions: '+name)
                else:
                    require(actual is None, 'Native accepted malformed input: '+name)
                if case['controller']:
                    expectation = artifacts/'inputs'/(name+'-expected.json')
                    controller = execute([args.reference, '--aggregate-reference', original, expectation],
                        folder/'controller.json', environment)
                    output = audit_controller(controller, case, inputs[name+'.json'], inputs[name+'-expected.json'])
                    resolved = folder/'native-resolved.json'
                    save(resolved, output)
                    replay = execute([args.reference, resolved, request_path], folder/'native-resolved-decisions.json', environment)
                    after = checked_decisions(replay, requests, 'reference')
                    if case['accepted']:
                        require(after == expected, 'Accepted snapshot changed authorization after native aggregation: '+name)
                    elif name == 'stale-empty':
                        probe = next(r for r in requests if r['username'] == 'app' and r['verb'] == 'get'
                                     and r['namespace'] == 'team-a' and r['resource'] == 'configmaps' and r['name'] == 'settings')
                        require(actual[probe['id']] == 'NoOpinion' and after[probe['id']] == 'Allow', 'Empty aggregate control did not change access')
                    elif name == 'stale-missing-secret':
                        probe = next(r for r in requests if r['username'] == 'app' and r['verb'] == 'get'
                                     and r['namespace'] == 'team-a' and r['resource'] == 'secrets' and r['name'] == 'settings')
                        require(actual[probe['id']] == 'NoOpinion' and after[probe['id']] == 'Allow',
                                'Stale aggregate safety control did not gain forbidden Secret access')
                    report['controller_cases'] += 1
                model = execute([args.model, original, contract_path, request_path], folder/'model.json', environment)
                receipt_path = Path(temporary, name+'-receipt.json')
                prepared = execute([args.soundcheck, 'rbac', 'prepare', original, '--receipt', receipt_path],
                    folder/'prepare.json', environment, json_output=False)
                if case['accepted']:
                    require(checked_decisions(model, requests, 'model') == expected
                            == smt_decisions(model, requests, folder, 'matrix', z3, environment), 'Native/model/SMT mismatch: '+name)
                    by_id = {r['id']: r for r in requests}
                    for row in model['data']['decisions']:
                        require(row['grants'] == expected_grants(case, by_id[row['id']]), 'Original grant indices changed: '+name)
                    require(prepared['returncode'] == 0 and receipt_path.is_file(), 'Preparation rejected valid aggregate: '+name)
                    output = prepared['stdout'].encode()
                    validate_receipt(read_json(receipt_path), original.read_bytes(), output, [])
                    target = folder/'prepared.json'
                    target.write_bytes(output)
                    compared = execute([args.reference, '--compare-policies', original, target], folder/'typed-policy.json', environment)
                    validate_policy_comparison(compared, original.read_bytes(), output, equal=True)
                    report['typed_policy_comparisons'] += 1
                    report['matrix_comparisons'] += len(requests)
                else:
                    require(checked_decisions(model, requests, 'model', allow_unsupported=True) is None,
                            'Connector accepted rejected aggregate: '+name)
                    require(prepared['returncode'] == 2 and prepared['stdout'] == '' and prepared['stderr']
                            and not receipt_path.exists(), 'Rejected preparation produced output/receipt: '+name)
                    report['rejected_controls'] += 1
                verification = execute([args.soundcheck, 'rbac', 'verify', original, '--contract', contract_path, '--format', 'json'],
                    folder/'verify.json', environment)
                witness = audit_report(verification, frozen, case['verdict'], case)
                if witness is not None:
                    path = folder/'witness.json'
                    save(path, [witness])
                    replay = execute([args.reference, original, path], folder/'witness-native.json', environment)
                    desired = 'Allow' if case['failed'] == 'secrets-not-granted' else 'NoOpinion'
                    require(checked_decisions(replay, [witness], 'reference') == {'witness': desired}, 'Native witness mismatch')
                    report['contract_witness_replays'] += 1
                report['cases'][name] = dict(result=case['verdict'], native_valid=case['native_valid'],
                    controller=case['controller'], accepted=case['accepted'], requests=len(requests) if case['accepted'] else 0)
                save(args.output, report)
                print(name+': '+case['verdict'], flush=True)
            baseline = artifacts/'inputs/unsafe-selected-secrets.json'
            for name, expected in [('match-labels', 'proved'), ('operator-regression', 'violated')]:
                folder, candidate = artifacts/('repair-'+name), artifacts/'inputs'/(name+'.json')
                comparison = execute([args.soundcheck, 'rbac', 'compare', baseline, candidate,
                    '--contract', contract_path, '--format', 'json'], folder/'compare.json', environment)
                witness = audit_report(comparison, frozen, expected, preservation=True)
                if witness is not None:
                    path = folder/'witness.json'
                    save(path, [witness])
                    before = execute([args.reference, baseline, path], folder/'before.json', environment)
                    after = execute([args.reference, candidate, path], folder/'after.json', environment)
                    require(checked_decisions(before, [witness], 'reference') == {'witness': 'Allow'}
                            and checked_decisions(after, [witness], 'reference') == {'witness': 'NoOpinion'}
                            and witness['username'] == 'operator', 'Preservation witness failed native replay')
                    report['preservation_witness_replays'] += 1
            require(report['controller_cases'] == sum(c['controller'] for c in cases())
                    and report['rejected_controls'] == sum(not c['accepted'] for c in cases())
                    and report['matrix_comparisons'] == len(requests)*sum(c['accepted'] for c in cases())
                    and report['typed_policy_comparisons'] == sum(c['accepted'] for c in cases())
                    and report['contract_witness_replays'] == sum(c['verdict'] == 'violated' for c in cases())
                    and report['preservation_witness_replays'] == 1, 'Incomplete campaign counters')
            require(all(digest(Path(path)) == value for path, value in report['input_sha256'].items()), 'Frozen inputs changed')
            require(all(digest(Path(path)) == value for path, value in report['binary_sha256'].items()), 'Tool binaries changed')
            audit_pins(planned_inputs(), read_json(HERE/'inputs.json'))
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, StopIteration) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print({key: report[key] for key in ['complete', 'controller_cases', 'matrix_comparisons',
        'rejected_controls', 'contract_witness_replays', 'preservation_witness_replays', 'failures']})
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
