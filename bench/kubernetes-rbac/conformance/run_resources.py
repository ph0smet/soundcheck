#!/usr/bin/env python3
"""Frozen synthetic resource-domain expectations against Kubernetes v1.34.0.

The catalogue and expected grants below are declared independently of the
connector. Original policy bytes go to the upstream authorizer. No deployed
objects or cluster API are contacted, and request authorization says nothing
about successful API execution or object effects.
"""
import argparse
import copy
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, DNS_LABEL, DNS_SUBDOMAIN, EXIT_CODES, decisions, digest,
                 execute, module_provenance, read_json, require, save,
                 smt_decisions, strict_json, strings, valid_dns)
from run_scopes import normalized, scope_matches as legacy_scope_matches

HERE = CORPUS/'resources'
PROFILE = 'kubernetes-rbac-v1.34-resource-read-write-v1'
LEGACY_PROFILE = 'kubernetes-rbac-v1.34-scoped-read-write-v3'
API = 'rbac.authorization.k8s.io'
VERBS = ['get', 'list', 'watch', 'update', 'patch', 'delete']
COLLECTIONS = ['list', 'watch']
# This literal registry is independent of the production connector. It is the
# frozen v5 domain; adding an entry is not a backwards-compatible v5 extension.
CATALOGUE = [('', 'configmaps', True), ('', 'secrets', True), ('', 'pods', True),
             ('', 'services', True), ('', 'endpoints', True), ('', 'nodes', False),
             ('apps', 'deployments', True), ('discovery.k8s.io', 'endpointslices', True)]
KINDS = {(resource if not group else resource+'.'+group): (group, resource, namespaced)
         for group, resource, namespaced in CATALOGUE}
IDENTITIES = {'app': [], 'ops': ['operators']}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)+'\n').encode()


def byte_hash(value):
    return hashlib.sha256(value).hexdigest()


def scope(resource='configmaps', group='', verb='get', namespace='team-a',
          names=None, subject='app'):
    return dict(subject=subject, verb=verb, api_group=group, resource=resource,
                namespace=namespace, names=names)


def clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **scope(**kwargs))


def contract(clauses=None, changes=(), version=5):
    if clauses is None:
        clauses = [clause('required', 'must_allow', names=['settings']),
                   clause('forbidden', 'must_not_grant', resource='secrets')]
    result = dict(schema_version=version, kind='kubernetes-rbac-access',
                  context=dict(schema_version=1, snapshot_complete=True,
                               identities=[dict(username=user, groups=list(groups))
                                           for user, groups in IDENTITIES.items()]),
                  clauses=copy.deepcopy(clauses), change_scope=copy.deepcopy(list(changes)))
    if version == 4:
        for selected in result['clauses']+result['change_scope']:
            require(selected.pop('api_group') == '', 'Legacy contracts remain core-only')
    return result


def rule(groups=('',), resources=('configmaps',), verbs=('get',), names=None):
    value = dict(apiGroups=list(groups), resources=list(resources), verbs=list(verbs))
    if names is not None:
        value['resourceNames'] = list(names)
    return value


def grant(tag, rules, namespace=None, subject='app', local_role=False):
    role_kind = 'Role' if local_role else 'ClusterRole'
    require(not local_role or namespace is not None, 'A Role needs a namespace')
    metadata = dict(name=tag)
    if local_role:
        metadata['namespace'] = namespace
    role = dict(apiVersion=API+'/v1', kind=role_kind, metadata=metadata,
                rules=copy.deepcopy(rules))
    binding = dict(apiVersion=API+'/v1',
                   kind='RoleBinding' if namespace is not None else 'ClusterRoleBinding',
                   metadata=dict(name=tag), roleRef=dict(apiGroup=API, kind=role_kind, name=tag),
                   subjects=[dict(kind='User', apiGroup=API, name=subject)])
    if namespace is not None:
        binding['metadata']['namespace'] = namespace
    return [role, binding]


def snapshot(items):
    return dict(apiVersion='v1', kind='List', items=copy.deepcopy(items))


def request(group, resource, verb='get', namespace='team-a', name='settings', user='app', id_='request'):
    return dict(id=id_, username=user, groups=IDENTITIES[user], verb=verb, apiGroup=group,
                resource=resource, namespace=namespace, name=name, resourceRequest=True, subresource='')


def matrix_requests():
    rows = []
    for group, resource, namespaced in CATALOGUE:
        for verb in VERBS:
            namespaces = ['team-a', 'team-b']+([''] if verb in COLLECTIONS else []) if namespaced else ['']
            for namespace in namespaces:
                for name in ['settings', 'other']+([''] if verb in COLLECTIONS else []):
                    rows.append(request(group, resource, verb, namespace, name, id_=str(len(rows))))
        # Identity isolation matters even when a role grants every resource.
        rows.append(request(group, resource, namespace='team-a' if namespaced else '',
                            user='ops', id_=str(len(rows))))
    return rows


def matrix_cases():
    """Each expected predicate describes one literal experiment, not RBAC parsing."""
    rows = matrix_requests()
    result = []

    def add(name, items, allowed):
        result.append(dict(id=name, snapshot=snapshot(items),
                           expected={row['id']: 'Allow' if allowed(row) else 'NoOpinion' for row in rows}))

    app = lambda r: r['username'] == 'app'
    global_all = rule(('*',), ('*',), VERBS)
    add('empty-policy', [], lambda _: False)
    add('whole-wildcards-global', grant('global', [global_all]), app)
    add('whole-wildcards-namespaced-role', grant('local', [global_all], 'team-a', local_role=True),
        lambda r: app(r) and r['namespace'] == 'team-a')
    add('whole-wildcards-rolebinding-to-clusterrole', grant('local-cluster', [global_all], 'team-a'),
        lambda r: app(r) and r['namespace'] == 'team-a')
    add('core-group-only', grant('core', [rule(('',), ('*',), VERBS)]),
        lambda r: app(r) and r['apiGroup'] == '')
    add('apps-group-only', grant('apps', [rule(('apps',), ('*',), VERBS)]),
        lambda r: app(r) and r['apiGroup'] == 'apps')
    add('discovery-group-only', grant('discovery', [rule(('discovery.k8s.io',), ('*',), VERBS)]),
        lambda r: app(r) and r['apiGroup'] == 'discovery.k8s.io')
    add('resource-exact-group-wildcard', grant('deployments', [rule(('*',), ('deployments',), VERBS)]),
        lambda r: app(r) and r['resource'] == 'deployments')
    add('wrong-group-pairs', grant('wrong', [rule(('extensions',), ('deployments',), VERBS),
                                          rule(('apps',), ('pods', 'nodes'), VERBS)]), lambda _: False)
    add('wildcard-like-literals', grant('literal', [rule(('app*',), ('deployments',), VERBS),
        rule(('apps',), ('deployments.apps',), VERBS), rule(('*',), ('pods/*', '*/status'), VERBS)]), lambda _: False)
    add('exact-resource-names', grant('named', [rule(('*',), ('*',), VERBS, ['settings'])]),
        lambda r: app(r) and r['name'] == 'settings')
    add('empty-resource-name', grant('empty', [rule(('*',), ('*',), VERBS, [''])]),
        lambda r: app(r) and r['name'] == '')
    add('star-resource-name-is-literal', grant('star', [rule(('*',), ('*',), VERBS, ['*'])]), lambda _: False)
    add('api-group-resource-cartesian-product', grant('cross', [rule(('', 'apps'), ('pods', 'deployments'), VERBS)]),
        lambda r: app(r) and (r['apiGroup'], r['resource']) in [('', 'pods'), ('apps', 'deployments')])
    return result


def contract_cases():
    result = []

    def add(name, spec, items, expected, failed=None, baseline=None, comparison=None,
            preservation_kind=None):
        result.append(dict(id=name, contract=spec, snapshot=snapshot(items), expected=expected,
                           failed=failed, baseline=None if baseline is None else snapshot(baseline),
                           comparison=comparison, preservation_kind=preservation_kind))

    required_deployment = clause('required-deployment', 'must_allow', resource='deployments',
                                 group='apps', names=['settings'])
    outside = scope(resource='deployments', group='apps', verb='patch',
                    namespace={'exclude': ['team-a']})
    scoped = contract([required_deployment, dict(name='outside-deployment-patch', kind='must_not_grant', **outside)], [outside])
    required = grant('deployment-reader', [rule(('apps',), ('deployments',), ['get'], ['settings'])], 'team-a')
    operator_nodes = grant('operator-nodes', [rule(('',), ('nodes',), ['get'])], subject='ops')
    operator_slices = grant('operator-slices', [rule(('discovery.k8s.io',), ('endpointslices',), ['get'])], 'team-a', subject='ops')
    keep = required+operator_nodes+operator_slices
    broad = grant('deployment-patch', [rule(('apps',), ('deployments',), ['patch'])])
    local = grant('deployment-patch-local', [rule(('apps',), ('deployments',), ['patch'])], 'team-a')
    before = keep+broad
    repaired = keep+broad[:1]+local
    add('deployment-unsafe', scoped, before, 'violated', 'outside-deployment-patch')
    add('deployment-minimal-repair', scoped, repaired, 'proved', baseline=before, comparison='proved')
    add('deployment-required-get-lost', scoped, operator_nodes+operator_slices+broad[:1]+local,
        'violated', 'required-deployment')
    add('node-regression-outside-clauses', scoped, required+operator_slices+broad[:1]+local+operator_nodes[:1],
        'proved', baseline=before, comparison='violated', preservation_kind='nodes')
    add('endpointslice-regression-outside-clauses', scoped, required+operator_nodes+broad[:1]+local+operator_slices[:1],
        'proved', baseline=before, comparison='violated', preservation_kind='endpointslices.discovery.k8s.io')

    node_required = clause('node-required', 'must_allow', resource='nodes', namespace=None, names=['settings'])
    node_forbidden = scope(resource='nodes', namespace=None, verb='patch')
    node_spec = contract([node_required, dict(name='node-patch-forbidden', kind='must_not_grant', **node_forbidden)], [node_forbidden])
    node_read = grant('node-reader', [rule(('',), ('nodes',), ['get'], ['settings'])])
    node_patch = grant('node-patcher', [rule(('',), ('nodes',), ['patch'])])
    add('node-unsafe', node_spec, node_read+node_patch, 'violated', 'node-patch-forbidden')
    add('node-repair', node_spec, node_read+node_patch[:1], 'proved',
        baseline=node_read+node_patch, comparison='proved')
    add('node-rolebinding-cannot-grant', node_spec,
        grant('node-local', [rule(('',), ('nodes',), ['get'], ['settings'])], 'team-a'),
        'violated', 'node-required')

    denied = clause('forbidden', 'must_not_grant', resource='secrets')
    add('wrong-api-group-required-access', contract([required_deployment, denied]),
        grant('wrong-api-group', [rule(('',), ('deployments',), ['get'])], 'team-a'),
        'violated', 'required-deployment')
    endpoint_deny = clause('all-namespace-list-forbidden', 'must_not_grant', resource='deployments',
                          group='apps', verb='list', namespace=None)
    collection = contract([required_deployment, endpoint_deny])
    local_list = grant('deployment-list', [rule(('apps',), ('deployments',), ['list'])], 'team-a')
    add('namespaced-list-does-not-grant-global', collection, required+local_list, 'proved')
    add('global-list-leak', collection, required+local_list+
        grant('global-list', [rule(('apps',), ('deployments',), ['list'])]),
        'violated', 'all-namespace-list-forbidden')

    common = grant('required-config', [rule(names=['settings'])], 'team-a')
    for resource, namespace in [('pods', 'team-b'), ('nodes', None)]:
        extra = grant('extra-'+resource, [rule(('',), (resource,), ['patch'])], namespace)
        for version in [4, 5]:
            add(f'v{version}-{resource}-unmentioned-preservation', contract(version=version),
                common+extra[:1], 'proved', baseline=common+extra,
                comparison='proved' if version == 4 else 'violated', preservation_kind=resource)
    return result


def validate_request(row, identities=IDENTITIES, version=5):
    require(isinstance(row, dict) and set(row) == {'id', 'username', 'groups', 'verb', 'apiGroup',
        'resource', 'namespace', 'name', 'resourceRequest', 'subresource'}, 'Unexpected request schema')
    require(isinstance(row['id'], str) and row['id'], 'Invalid request id')
    user = row['username']
    require(isinstance(user, str) and user in identities, 'Unknown frozen identity')
    require(strings(row['groups'], nonempty=True) and len(set(row['groups'])) == len(row['groups'])
            and sorted(row['groups']) == sorted(identities[user]), 'Identity groups differ')
    require(row['resourceRequest'] is True and row['subresource'] == '' and row['verb'] in VERBS,
            'Request outside supported verbs/resource/subresource domain')
    entries = CATALOGUE if version == 5 else CATALOGUE[:2]
    selected = [item for item in entries if item[:2] == (row['apiGroup'], row['resource'])]
    require(len(selected) == 1, 'Unknown API group/resource pair')
    collection = row['verb'] in COLLECTIONS
    if selected[0][2]:
        require((collection and row['namespace'] == '') or valid_dns(row['namespace'], 63, DNS_LABEL),
                'Invalid namespaced request')
    else:
        require(row['namespace'] == '', 'Node request is not cluster-scoped')
    require((collection and row['name'] == '') or valid_dns(row['name'], 253, DNS_SUBDOMAIN),
            'Invalid effective authorization name')


def witness_request(report, spec):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'}, 'Invalid typed witness')
    require(isinstance(obj['resource_kind'], str) and obj['resource_kind'] in KINDS, 'Unknown resource discriminator')
    group, resource, _ = KINDS[obj['resource_kind']]
    row = dict(id='witness', username=witness.get('principal'), groups=witness.get('identity_groups'),
               verb=witness.get('action'), apiGroup=group, resource=resource, namespace=obj['namespace'],
               name=obj['name'], resourceRequest=True, subresource='')
    identities = {i['username']: i['groups'] for i in spec['context']['identities']}
    validate_request(row, identities, spec['schema_version'])
    require(strings(witness.get('granting_rules'), nonempty=True) and
            len(set(witness['granting_rules'])) == len(witness['granting_rules']), 'Invalid witness grant labels')
    return row


def scope_matches(selected, row):
    return selected.get('api_group', '') == row['apiGroup'] and legacy_scope_matches(selected, row)


def audit_report(execution, spec, expected, comparison=False):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected and
            execution.get('returncode') == EXIT_CODES[expected], 'Unexpected report verdict/exit')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Wrong report schema')
    require(report.get('property') == ('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'),
            'Wrong verification property')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') ==
            (PROFILE if spec['schema_version'] == 5 else LEGACY_PROFILE) and
            assurance.get('status') == 'within_profile' and assurance.get('findings') == [], 'Wrong assurance')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and
            frozen['schema_version'] == spec['schema_version'] and frozen.get('kind') == spec['kind'] and
            isinstance(frozen.get('canonical'), str), 'Missing frozen spec identity')
    require(encoded(normalized(strict_json(frozen['canonical']))) == encoded(normalized(spec)),
            'Frozen contract was changed')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'proved':
        require(report.get('clause') is None, 'Proof contains a failed clause')
    return report


def url_cases():
    rows = []

    def add(id_, method, url, group, resource, verb, namespace, name, supported=True, subresource=''):
        row = request(group, resource, verb, namespace, name, id_=id_)
        row['subresource'] = subresource
        # The URL-policy is an all-resource ClusterRole bound only in team-a.
        rows.append(dict(request=dict(id=id_, username='app', groups=[], method=method, url=url),
                         attributes=dict(**{k: v for k, v in row.items() if k != 'id'}, apiVersion='v1',
                                         path=url.split('?', 1)[0]), supported=supported,
                         decision='Allow' if namespace == 'team-a' else 'NoOpinion'))

    for group, resource, namespaced in CATALOGUE:
        prefix = '/api/v1' if not group else '/apis/'+group+'/v1'
        base = prefix+('/namespaces/team-a' if namespaced else '')+'/'+resource
        namespace = 'team-a' if namespaced else ''
        for method, verb in [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch'), ('DELETE', 'delete')]:
            add(resource+'-'+verb, method, base+'/settings', group, resource, verb, namespace, 'settings')
        for verb in COLLECTIONS:
            query = '?watch=true' if verb == 'watch' else ''
            add(resource+'-'+verb, 'GET', base+query, group, resource, verb, namespace, '')
            selected = query+('&' if query else '?')+'fieldSelector=metadata.name%3Dsettings'
            add(resource+'-'+verb+'-selected', 'GET', base+selected, group, resource, verb, namespace, 'settings')
            if namespaced:
                add(resource+'-'+verb+'-all-namespaces', 'GET', prefix+'/'+resource+query,
                    group, resource, verb, '', '')
    add('namespace-special-named', 'GET', '/api/v1/namespaces/team-a', '', 'namespaces', 'get', 'team-a', 'team-a', False)
    add('namespace-special-collection', 'GET', '/api/v1/namespaces?fieldSelector=metadata.name%3Dteam-a',
        '', 'namespaces', 'list', '', 'team-a', False)
    add('pod-log-subresource', 'GET', '/api/v1/namespaces/team-a/pods/settings/log', '', 'pods', 'get',
        'team-a', 'settings', False, 'log')
    add('pod-create', 'POST', '/api/v1/namespaces/team-a/pods', '', 'pods', 'create', 'team-a', '', False)
    add('pod-deletecollection', 'DELETE', '/api/v1/namespaces/team-a/pods', '', 'pods', 'deletecollection', 'team-a', '', False)
    return rows


def audit_urls(execution, expected):
    value = execution.get('data')
    require(execution.get('returncode') == 0 and isinstance(value, dict) and
            type(value.get('schema_version')) is int and value['schema_version'] == 1 and
            value.get('kind') == 'rbac_request_url_authorization' and value.get('valid') is True and
            value.get('validation_errors') == [], 'Invalid native URL envelope')
    rows = value.get('decisions')
    require(isinstance(rows, list) and len(rows) == len(expected), 'Missing URL extraction rows')
    wanted = {row['request']['id']: row for row in expected}
    require(len(wanted) == len(expected), 'Duplicate planned URL id')
    actual = {}
    for row in rows:
        require(isinstance(row, dict) and row.get('id') in wanted and row['id'] not in actual,
                'Duplicate/unexpected URL decision id')
        fixed = wanted[row['id']]
        require(encoded(row.get('attributes')) == encoded(fixed['attributes']) and
                row.get('decision') == fixed['decision'] and row.get('error') == '' and
                isinstance(row.get('reason'), str) and row.get('field_selector_error') is False and
                row.get('label_selector_error') is False, 'Native URL extraction/authorization differs: '+row['id'])
        actual[row['id']] = row['attributes']
    return actual


def rejection_requests():
    valid = request('apps', 'deployments')
    changes = [('unknown-group', {'apiGroup': 'extensions'}), ('raw-dotted-resource', {'resource': 'deployments.apps'}),
        ('unknown-custom-resource', {'apiGroup': 'example.test', 'resource': 'widgets'}),
        ('node-with-namespace', {'apiGroup': '', 'resource': 'nodes'}),
        ('namespace-resource', {'apiGroup': '', 'resource': 'namespaces'}),
        ('named-all-namespace', {'namespace': ''}), ('empty-named-operation', {'name': ''}),
        ('create', {'verb': 'create', 'name': ''}), ('deletecollection', {'verb': 'deletecollection', 'name': ''}),
        ('subresource', {'subresource': 'scale'}), ('non-resource', {'resourceRequest': False}),
        ('wildcard-name', {'name': '*'}), ('non-dns-name', {'name': 'UPPER'}),
        ('long-name', {'name': 'a'*254}), ('long-namespace', {'namespace': 'a'*64})]
    return [dict(valid, id=id_, **change) for id_, change in changes]


def planned_inputs():
    inputs = {'contract.json': encoded(contract()), 'matrix/requests.json': encoded(matrix_requests())}
    for case in matrix_cases():
        for key in ['snapshot', 'expected']:
            inputs['matrix/'+case['id']+'/'+key+'.json'] = encoded(case[key])
    for case in contract_cases():
        for key in ['contract', 'snapshot', 'baseline']:
            if case[key] is not None:
                inputs['contracts/'+case['id']+'/'+key+'.json'] = encoded(case[key])
        inputs['contracts/'+case['id']+'/expected.json'] = encoded({key: case[key] for key in
            ['expected', 'failed', 'comparison', 'preservation_kind']})
    urls = url_cases()
    inputs['urls/requests.json'] = encoded([row['request'] for row in urls])
    inputs['urls/expected.json'] = encoded(urls)
    inputs['urls/snapshot.json'] = encoded(snapshot(grant('url-local', [rule(('*',), ('*',), ['*'])], 'team-a')))
    inputs['rejections/requests.json'] = encoded(rejection_requests())
    return inputs


def audit_pins(inputs, pins):
    require(isinstance(pins, dict) and set(inputs) == set(pins), 'Synthetic input pin inventory differs')
    for key, value in inputs.items():
        require(pins[key] == dict(sha256=byte_hash(value), bytes=len(value)), 'Synthetic input pin mismatch: '+key)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    result = dict(complete=False, profile=PROFILE, matrix_comparisons=0, url_comparisons=0, contract_native_checks=0,
                  rejected_requests=0, contract_witness_replays=0, preservation_witness_replays=0,
                  cases={}, failures=[], input_sha256={}, limits=[
        'Frozen synthetic policies and initial RBAC authorization only; no cluster/deployment contacted.',
        'Finite native/model/SMT comparisons do not prove the encoder correct for all inputs.',
        'DNS1123 authorization-name subset; no object-body validation, route existence or API execution claims.',
        'Schemas 1-4 retain the core ConfigMap/Secret domain; schema 5 fixes eight resource/group pairs.'])
    save(args.output, result)
    try:
        result['reference'] = module_provenance(args.module_metadata)
        inputs = planned_inputs()
        audit_pins(inputs, read_json(HERE/'inputs.json'))
        require((HERE/'contract.json').read_bytes() == inputs['contract.json'], 'Runnable contract differs from frozen fixture')
        artifacts = args.output.parent/'artifacts'
        for key, value in inputs.items():
            path = artifacts/key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            result['input_sha256'][str(path)] = digest(path)
        source_hashes = {str(path): digest(path) for path in [Path(__file__),
            Path(__file__).with_name('run.py'), Path(__file__).with_name('run_scopes.py'),
            Path(__file__).with_name('run_write_access.py'), HERE/'inputs.json', HERE/'contract.json']}
        result['source_sha256'] = source_hashes
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 is required')
        tools = [args.reference, args.model, args.soundcheck, Path(z3)]
        result['binary_sha256'] = {str(path): digest(path) for path in tools}
        save(args.output, result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-resource-z3-') as directory:
            Path(directory, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=directory+os.pathsep+os.environ.get('PATH', ''))

            def model_and_native(manifest, spec_path, rows, folder, label, expected=None):
                for row in rows:
                    validate_request(row, version=read_json(spec_path)['schema_version'])
                request_path = folder/(label+'-requests.json')
                save(request_path, rows)
                native = decisions(execute([args.reference, manifest, request_path], folder/(label+'-reference.json'), environment), rows, 'reference')
                model = execute([args.model, manifest, spec_path, request_path], folder/(label+'-model.json'), environment)
                mine = decisions(model, rows, 'model')
                symbolic = smt_decisions(model, rows, folder, label, z3, environment)
                require(native == mine == symbolic, 'Native/concrete/SMT mismatch: '+label)
                if expected is not None:
                    require(native == expected, 'Literal expected grants differ: '+label)
                return native

            rows = matrix_requests()
            for case in matrix_cases():
                folder = artifacts/'matrix'/case['id']
                model_and_native(folder/'snapshot.json', artifacts/'contract.json', rows, folder, 'matrix', case['expected'])
                result['matrix_comparisons'] += len(rows)
                result['cases'][case['id']] = dict(matrix_comparisons=len(rows))
                print(case['id']+': literal/native/concrete/SMT agree', flush=True)
                save(args.output, result)

            for case in contract_cases():
                folder = artifacts/'contracts'/case['id']
                spec_path, manifest = folder/'contract.json', folder/'snapshot.json'
                spec = case['contract']
                finite = [row for row in rows if spec['schema_version'] == 5 or
                          (row['apiGroup'] == '' and row['resource'] in ['configmaps', 'secrets'])]
                finite_path = folder/'finite-requests.json'
                save(finite_path, finite)
                observed = decisions(execute([args.reference, manifest, finite_path],
                    folder/'finite-reference.json', environment), finite, 'reference')
                failures = []
                for selected in spec['clauses']:
                    points = [row for row in finite if scope_matches(selected, row)]
                    require(points, 'Finite corpus does not inhabit clause '+selected['name'])
                    wanted = 'Allow' if selected['kind'] == 'must_allow' else 'NoOpinion'
                    if any(observed[row['id']] != wanted for row in points):
                        failures.append(selected['name'])
                require(bool(failures) == (case['expected'] == 'violated'),
                        'Literal contract expectation differs from finite native decisions: '+case['id'])
                if failures:
                    require(failures[0] == case['failed'], 'Unexpected first native failing clause')
                result['contract_native_checks'] += len(finite)
                if case['baseline'] is not None:
                    prior = decisions(execute([args.reference, folder/'baseline.json', finite_path],
                        folder/'finite-baseline-reference.json', environment), finite, 'reference')
                    changed = [row for row in finite if observed[row['id']] != prior[row['id']] and
                               not any(scope_matches(selected, row) for selected in spec['change_scope'])]
                    require(bool(changed) == (case['comparison'] == 'violated'),
                            'Literal preservation expectation differs from finite native decisions: '+case['id'])
                    result['contract_native_checks'] += len(finite)

                def replay(report, comparison=False):
                    row = witness_request(report, spec)
                    if comparison:
                        require(report.get('property') == 'rbac-repair-preservation' and
                                isinstance(report.get('clause'), dict) and report['clause'].get('kind') == 'must_preserve' and
                                report['clause'].get('name') == 'preservation-outside-change-scope', 'Wrong preservation obligation')
                        require(not any(scope_matches(s, row) for s in spec['change_scope']), 'Preservation witness inside approved changes')
                        require(report['counterexample']['object_request']['resource_kind'] == case['preservation_kind'], 'Wrong preservation resource')
                        before = model_and_native(folder/'baseline.json', spec_path, [row], folder, 'preservation-before')['witness']
                        after = model_and_native(manifest, spec_path, [row], folder, 'preservation-after')['witness']
                        require(before != after, 'Preservation witness has no native decision change')
                        require(bool(report['counterexample']['granting_rules']) == (after == 'Allow'),
                                'Preservation witness grant labels contradict native candidate decision')
                        result['preservation_witness_replays'] += 1
                    else:
                        reported = report.get('clause')
                        require(isinstance(reported, dict), 'Missing clause identity')
                        selected = [c for c in spec['clauses'] if c['name'] == reported.get('name')]
                        require(len(selected) == 1 and selected[0]['name'] == case['failed'] and
                                selected[0]['kind'] == reported.get('kind') and scope_matches(selected[0], row), 'Witness is outside expected clause')
                        decision = model_and_native(manifest, spec_path, [row], folder, 'clause-replay')['witness']
                        require(decision == ('Allow' if selected[0]['kind'] == 'must_not_grant' else 'NoOpinion'), 'Witness does not violate native decision')
                        require(bool(report['counterexample']['granting_rules']) == (decision == 'Allow'),
                                'Contract witness grant labels contradict native decision')
                        result['contract_witness_replays'] += 1

                verified = audit_report(execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', spec_path,
                    '--format', 'json'], folder/'verify.json', environment), spec, case['expected'])
                result['cases'][case['id']] = dict(contract=verified['result'])
                if verified['result'] == 'violated':
                    replay(verified)
                if case['baseline'] is not None:
                    compared = audit_report(execute([args.soundcheck, 'rbac', 'compare', folder/'baseline.json', manifest,
                        '--contract', spec_path, '--format', 'json'], folder/'compare.json', environment), spec, case['comparison'], comparison=True)
                    result['cases'][case['id']]['comparison'] = compared['result']
                    if compared['result'] == 'violated':
                        replay(compared, True)
                print(case['id']+': '+str(result['cases'][case['id']]), flush=True)
                save(args.output, result)

            folder = artifacts/'urls'
            fixed = url_cases()
            extracted = audit_urls(execute([args.reference, '--request-urls', folder/'snapshot.json', folder/'requests.json'],
                                           folder/'reference.json', environment), fixed)
            supported, excluded = [], []
            for case in fixed:
                id_ = case['request']['id']
                attributes = dict(extracted[id_])
                del attributes['apiVersion'], attributes['path']
                row = dict(attributes, id=id_)
                (supported if case['supported'] else excluded).append(row)
            wanted = {case['request']['id']: case['decision'] for case in fixed if case['supported']}
            model_and_native(folder/'snapshot.json', artifacts/'contract.json', supported, folder, 'extracted', wanted)
            result['url_comparisons'] = len(fixed)
            # Domain rejections are intentional, including native-valid Namespace
            # requests whose authorization namespace differs from Nodes.
            for row in rejection_requests()+excluded:
                request_path = artifacts/'rejections'/(row['id']+'.json')
                save(request_path, [row])
                model = execute([args.model, folder/'snapshot.json', artifacts/'contract.json', request_path],
                                artifacts/'rejections'/(row['id']+'-model.json'), environment)
                require(decisions(model, [row], 'model', allow_unsupported=True) is None,
                        'Unsupported request received a model decision: '+row['id'])
                result['rejected_requests'] += 1
            require(all(digest(Path(path)) == sha for path, sha in result['input_sha256'].items()), 'Planned inputs changed during execution')
            require(all(digest(Path(path)) == sha for path, sha in source_hashes.items()), 'Campaign source/pins changed during execution')
            require(all(digest(Path(path)) == sha for path, sha in result['binary_sha256'].items()), 'Binaries changed during execution')
            audit_pins(planned_inputs(), read_json(HERE/'inputs.json'))
            result['inputs_unchanged'] = True
            result['binaries_unchanged'] = True
            result['complete'] = True
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result['failures'].append(str(error))
    save(args.output, result)
    print(json.dumps({key: result[key] for key in ['complete', 'matrix_comparisons', 'url_comparisons', 'contract_native_checks',
        'rejected_requests', 'contract_witness_replays', 'preservation_witness_replays', 'failures']}))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
