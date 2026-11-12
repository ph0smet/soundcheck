#!/usr/bin/env python3
"""Frozen schema-8 SSA authorization experiments against Kubernetes 1.34.0.

SSA observations come from the native HTTP authorization/PATCH/generic-store
path, with hypothetical in-memory object states and native dry-run processing.
Expectations are literal grant experiments frozen before production comparison.
"""
import argparse
import copy
import os
import shutil
import tempfile
from pathlib import Path

from run import (DNS_LABEL, DNS_SUBDOMAIN, EXIT_CODES, decisions, digest, execute,
                 module_provenance, read_json, require, save, smt_decisions,
                 strict_json, strings, valid_dns)
from run_scopes import normalized
import run_subresources as legacy
import run_collection_writes as collections
import run_resources as resources
from run_resources import IDENTITIES, rule, grant, snapshot, encoded, byte_hash, audit_pins

HERE = Path(__file__).resolve().parent.parent/'apply'
PROFILE = 'kubernetes-rbac-v1.34-apply-v1'
NEW_OPERATIONS = ['apply-existing', 'apply-missing']
CATALOGUE = [(g, r, '', ns, collections.VERBS + NEW_OPERATIONS) for g, r, ns in resources.CATALOGUE]
CATALOGUE += [(g, r, s, ns, [v for _, v in methods]) for g, r, s, ns, methods in legacy.CATALOGUE]
KINDS = legacy.KINDS
SOURCE_FILES = {
    'kubernetes': ['plugin/pkg/auth/authorizer/rbac/rbac.go', 'pkg/apis/rbac/v1/evaluation_helpers.go',
        'test/integration/apiserver/apply/apply_test.go'] +
        ['pkg/registry/'+p+'/'+f for p in ['core/configmap', 'core/secret', 'core/pod', 'core/service',
            'core/endpoint', 'core/node', 'apps/deployment', 'discovery/endpointslice']
         for f in ['strategy.go', 'storage/storage.go']],
    'apiserver': ['pkg/endpoints/request/requestinfo.go', 'pkg/endpoints/filters/requestinfo.go',
        'pkg/endpoints/filters/authorization.go', 'pkg/endpoints/handlers/patch.go',
        'pkg/endpoints/handlers/update.go', 'pkg/endpoints/handlers/namer.go',
        'pkg/endpoints/handlers/rest.go', 'pkg/registry/generic/registry/store.go',
        'pkg/registry/generic/registry/dryrun.go'],
}
LINKAGE = {
    'request-info': ('apiserver', 'pkg/endpoints/filters/requestinfo.go', 28, 'pkg/endpoints/filters.WithRequestInfo'),
    'authorization-filter': ('apiserver', 'pkg/endpoints/filters/authorization.go', 53, 'pkg/endpoints/filters.WithAuthorization'),
    'patch-handler': ('apiserver', 'pkg/endpoints/handlers/patch.go', 68, 'pkg/endpoints/handlers.PatchResource'),
    'generic-store-update': ('apiserver', 'pkg/registry/generic/registry/store.go', 617, 'pkg/registry/generic/registry.(*Store).Update'),
    'native-dry-run-update': ('apiserver', 'pkg/registry/generic/registry/dryrun.go', 74, 'pkg/registry/generic/registry.(*DryRunnableStorage).GuaranteedUpdate'),
}
for _resource, _path, _line, _type in [
        ('configmaps', 'core/configmap', 74, 'strategy'), ('secrets', 'core/secret', 72, 'strategy'),
        ('pods', 'core/pod', 136, 'podStrategy'), ('services', 'core/service', 104, 'svcStrategy'),
        ('endpoints', 'core/endpoint', 70, 'endpointsStrategy'), ('nodes', 'core/node', 75, 'nodeStrategy'),
        ('deployments', 'apps/deployment', 105, 'deploymentStrategy'),
        ('endpointslices', 'discovery/endpointslice', 115, 'endpointSliceStrategy')]:
    LINKAGE['strategy-'+_resource] = ('kubernetes', 'pkg/registry/'+_path+'/strategy.go', _line,
        'pkg/registry/'+_path+'.'+_type+'.AllowCreateOnUpdate')


def audit_linkage(execution):
    require(type(execution.get('returncode')) is int and execution['returncode'] == 0, 'Native linkage command failed')
    value = execution.get('data')
    require(isinstance(value, dict) and set(value) == {'schema_version', 'kind', 'go_version', 'modules', 'functions'}, 'Invalid native linkage shape')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['kind'] == 'rbac_apply_native_linkage', 'Invalid native linkage schema')
    require(isinstance(value['go_version'], str) and value['go_version'].startswith('go1.'), 'Missing reference toolchain version')
    require(isinstance(value['modules'], dict), 'Missing compiled modules')
    versions = {'kubernetes': 'v1.34.0', 'apiserver': 'v0.34.0', 'api': 'v0.34.0', 'apimachinery': 'v0.34.0'}
    for module, version in versions.items():
        require(value['modules'].get('k8s.io/'+module) == version, 'Native compiled module differs: '+module)
    require(isinstance(value['functions'], dict) and set(value['functions']) == set(LINKAGE), 'Native linked function inventory differs')
    for label, (module, source, line, function) in LINKAGE.items():
        observed = value['functions'][label]
        require(isinstance(observed, dict) and set(observed) == {'function', 'file', 'line'}, 'Invalid linked function')
        # Go may attribute an entry PC to the declaration or first statement
        # (notably one-return strategy methods). Both are in the pinned body.
        require(observed['function'] == 'k8s.io/'+module+'/'+function and type(observed['line']) is int and observed['line'] in [line, line+1],
            'Wrong native implementation: '+label)
        require(isinstance(observed['file'], str) and observed['file'].endswith('k8s.io/'+module+'@'+versions[module]+'/'+source),
            'Wrong native source linkage: '+label)
    return value


def scope(resource='configmaps', group='', subresource='', operation='get', namespace='team-a', names=None, subject='app'):
    return dict(subject=subject, operation=operation, api_group=group, resource=resource,
                subresource=subresource, namespace=namespace, names=names)


def clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **scope(**kwargs))


def contract(clauses=None, changes=None, version=8):
    if version == 7:
        return legacy.contract([legacy.clause('required', 'must_allow', names=['settings']),
                                legacy.clause('forbidden', 'must_not_grant', resource='secrets')], [])
    if clauses is None:
        clauses = [clause('required-apply-existing', 'must_allow', operation='apply-existing', names=['settings']),
                   clause('forbidden-apply-missing', 'must_not_grant', operation='apply-missing')]
    if changes is None:
        changes = [scope(operation='apply-missing')]
    return resources.contract(clauses, changes, version=8)


def request(group='', resource='configmaps', subresource='', operation='apply-missing', namespace='team-a', name='settings', user='app', id_='request'):
    return dict(id=id_, username=user, groups=list(IDENTITIES[user]), operation=operation, apiGroup=group,
                resource=resource, namespace=namespace, name=name, resourceRequest=True, subresource=subresource)


def upgrade_row(row):
    result = dict(row)
    result['operation'] = result.pop('verb')
    return result


def old_row(row):
    result = dict(row)
    result['verb'] = result.pop('operation')
    return result


def matrix_requests():
    rows = []
    # Both identities and fresh namespace/name representatives cover every
    # one of the 99 operation classes, including the entire legacy domain.
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        for operation in operations:
            collection_read = subresource == '' and operation in ['list', 'watch']
            collection_write = subresource == '' and operation in ['create', 'deletecollection']
            namespaces = ['team-a', 'team-b', 'fresh-ns'] + ([''] if collection_read else []) if namespaced else ['']
            names = [''] if collection_write else ['settings', 'other', 'fresh-name'] + ([''] if collection_read else [])
            for namespace in namespaces:
                for name in names:
                    for user in IDENTITIES:
                        rows.append(request(group, resource, subresource, operation=operation, namespace=namespace,
                            name=name, user=user, id_=str(len(rows))))
    return rows


def matrix_cases():
    rows, cases = matrix_requests(), []
    # Predicates describe the explicitly constructed experiment, not an RBAC
    # parser/evaluator. In particular, no expected value reads policy objects.
    def add(id_, items, permitted):
        expected = {}
        for r in rows:
            operation = r['operation']
            verbs = ['patch'] if operation in NEW_OPERATIONS else [operation]
            stages = ['Allow' if permitted(dict(r, verb=verbs[0])) else 'NoOpinion']
            if operation == 'apply-missing' and stages[0] == 'Allow':
                stages.append('Allow' if permitted(dict(r, verb='create')) else 'NoOpinion')
            expected[r['id']] = dict(decision='Allow' if all(d == 'Allow' for d in stages) else 'NoOpinion', stages=stages)
        cases.append(dict(id=id_, snapshot=snapshot(items), expected=expected))
    app = lambda r: r['username'] == 'app'
    add('empty-policy', [], lambda _: False)
    add('whole-wildcards', grant('all', [rule(('*',), ('*',), ['*'])]), app)
    for verb in ['patch', 'create', 'update', 'get']:
        add(verb+'-only', grant(verb, [rule(('*',), ('*',), [verb])]), lambda r, v=verb: app(r) and r['verb'] == v)
    both = rule(('*',), ('*',), ['patch', 'create'])
    add('same-rule-both-stages', grant('both', [both]), lambda r: app(r) and r['verb'] in ['patch', 'create'])
    add('separate-roles-both-stages', grant('patch', [rule(('*',), ('*',), ['patch'])])+grant('create', [rule(('*',), ('*',), ['create'])]),
        lambda r: app(r) and r['verb'] in ['patch', 'create'])
    for names, label in [(None, 'omitted'), ([], 'empty-list'), (['settings'], 'named'), ([''], 'empty-name'), (['*'], 'literal-star'), (['', 'settings'], 'mixed')]:
        add(label+'-resourceNames', grant(label, [rule(('*',), ('*',), ['patch', 'create'], names)]),
            lambda r, ns=names: app(r) and r['verb'] in ['patch', 'create'] and (not ns or r['name'] in ns))
    add('disjoint-stage-names', grant('patch', [rule(('*',), ('*',), ['patch'], ['settings'])])+
        grant('create', [rule(('*',), ('*',), ['create'], ['other'])]),
        lambda r: app(r) and ((r['verb'] == 'patch' and r['name'] == 'settings') or (r['verb'] == 'create' and r['name'] == 'other')))
    add('empty-create-does-not-complete-apply', grant('patch', [rule(('*',), ('*',), ['patch'])])+
        grant('create', [rule(('*',), ('*',), ['create'], [''])]),
        lambda r: app(r) and (r['verb'] == 'patch' or (r['verb'] == 'create' and r['name'] == '')))
    for local in [False, True]:
        add('namespaced-'+('role' if local else 'clusterrole'), grant('local', [both], 'team-a', local_role=local),
            lambda r: app(r) and r['namespace'] == 'team-a' and r['verb'] in ['patch', 'create'])
    add('disjoint-stage-namespaces', grant('patch', [rule(('*',), ('*',), ['patch'])], 'team-a')+
        grant('create', [rule(('*',), ('*',), ['create'])], 'team-b'),
        lambda r: app(r) and ((r['verb'] == 'patch' and r['namespace'] == 'team-a') or (r['verb'] == 'create' and r['namespace'] == 'team-b')))
    add('disjoint-stage-identities', grant('patch', [rule(('*',), ('*',), ['patch'])])+
        grant('create', [rule(('*',), ('*',), ['create'])], subject='ops'),
        lambda r: (app(r) and r['verb'] == 'patch') or (r['username'] == 'ops' and r['verb'] == 'create'))
    for group, label in [('', 'core'), ('apps', 'apps'), ('discovery.k8s.io', 'discovery')]:
        add(label+'-group', grant(label, [rule((group,), ('*',), ['patch', 'create'])]),
            lambda r, g=group: app(r) and r['apiGroup'] == g and r['verb'] in ['patch', 'create'])
    add('disjoint-stage-resources', grant('patch', [rule(('',), ['pods'], ['patch'])])+
        grant('create', [rule(('',), ['secrets'], ['create'])]),
        lambda r: app(r) and r['apiGroup'] == '' and r['subresource'] == '' and
        ((r['verb'] == 'patch' and r['resource'] == 'pods') or (r['verb'] == 'create' and r['resource'] == 'secrets')))
    add('subresource-grants-do-not-complete-base-apply', grant('sub', [rule(('*',), ['*/status', 'pods/exec', 'serviceaccounts/token'], ['patch', 'create'])]),
        lambda r: app(r) and ((r['subresource'] == 'status' and r['verb'] == 'patch') or
            (r['resource'] in ['pods', 'serviceaccounts'] and r['subresource'] in ['exec', 'token'] and r['verb'] == 'create')))
    add('operation-is-not-rbac-verb', grant('literal', [rule(('*',), ('*',), NEW_OPERATIONS)]), lambda _: False)
    add('resource-parent-star-is-literal', grant('literal', [rule(('*',), ['pods/*', '*/*'], ['*'])]), lambda _: False)
    operators = grant('operators', [both])
    operators[1]['subjects'] = [dict(kind='Group', apiGroup=resources.API, name='operators')]
    add('trusted-group-both-stages', operators, lambda r: r['username'] == 'ops' and r['verb'] in ['patch', 'create'])
    aggregate = grant('aggregate', [both])
    aggregate[0]['aggregationRule'] = dict(clusterRoleSelectors=[dict(matchLabels={'conformance.soundcheck/apply': 'true'})])
    leaf = grant('leaf', [both])[0]
    leaf['metadata']['labels'] = {'conformance.soundcheck/apply': 'true'}
    add('resolved-aggregate-both-stages', [leaf]+aggregate, lambda r: app(r) and r['verb'] in ['patch', 'create'])
    return cases


def contract_cases():
    cases = []
    def add(id_, spec, items, expected, failed=None, baseline=None, comparison=None, preservation=None):
        cases.append(dict(id=id_, contract=spec, snapshot=snapshot(items), expected=expected, failed=failed,
            baseline=None if baseline is None else snapshot(baseline), comparison=comparison, preservation=preservation))
    patch = grant('patch', [rule(('',), ['configmaps'], ['patch'], ['settings'])], 'team-a')
    create = grant('create', [rule(('',), ['configmaps'], ['create'], ['settings'])], 'team-a')
    spec = contract()
    add('unsafe-apply-create', spec, patch+create, 'violated', 'forbidden-apply-missing')
    # Removing a named create grant has no effect on collection-create, but
    # removes apply-missing while preserving named patch/apply-existing.
    add('minimal-apply-repair', spec, patch+create[:1], 'proved', baseline=patch+create, comparison='proved')
    add('lost-existing-functionality', spec, patch[:1]+create[:1], 'violated', 'required-apply-existing')
    add('existing-needs-only-patch', spec, patch, 'proved')
    for group, resource, namespaced in resources.CATALOGUE:
        ns = 'team-a' if namespaced else None
        for operation in NEW_OPERATIONS:
            args = dict(group=group, resource=resource, operation=operation, namespace=ns)
            paired = contract([clause('required', 'must_allow', **args, names=['settings']),
                clause('forbidden-other', 'must_not_grant', **args, names={'exclude': ['settings'], 'include_empty': False})], [])
            verbs = ['patch'] if operation == 'apply-existing' else ['patch', 'create']
            items = grant('named', [rule((group,), [resource], verbs, ['settings'])], ns)
            add(resource+'-'+operation, paired, items, 'proved')
    must_apply = contract([clause('required', 'must_allow', operation='apply-missing', names=['settings']),
                          clause('forbidden', 'must_not_grant', resource='secrets')], [])
    add('required-apply-missing-needs-create', must_apply, patch, 'violated', 'required')
    add('separate-roles-satisfy-apply', must_apply, patch+create, 'proved')
    empty_create = grant('create', [rule(('',), ['configmaps'], ['create'], [''])], 'team-a')
    add('empty-create-name-is-insufficient', must_apply, patch+empty_create, 'violated', 'required')
    named_only = contract([clause('required', 'must_allow', operation='apply-missing', names=['settings']),
                          clause('collection-forbidden', 'must_not_grant', operation='create', names={'empty': True})], [])
    add('named-apply-create-does-not-grant-collection-create', named_only, patch+create, 'proved')
    node_spec = contract([clause('required', 'must_allow', resource='nodes', operation='apply-missing', namespace=None),
                          clause('forbidden', 'must_not_grant', resource='secrets')], [])
    add('rolebinding-cannot-complete-node-apply', node_spec, grant('local-node', [rule(('',), ['nodes'], ['patch', 'create'])], 'team-a'), 'violated', 'required')
    selected = contract([clause('required', 'must_allow', operation='apply-missing', names=['settings'], namespace={'include': ['team-b', 'team-a']}),
        clause('forbidden', 'must_not_grant', operation='apply-missing', namespace={'exclude': ['team-a', 'team-b']}, names={'exclude': ['settings'], 'include_empty': False})], [])
    add('namespace-and-name-selectors', selected, patch+create+
        grant('both-b', [rule(('',), ['configmaps'], ['patch', 'create'], ['settings'])], 'team-b'), 'proved')
    # Keep preservation controls at settings only. This freezes the changed
    # coordinate, while both identities/all99 operation classes remain checked.
    common = grant('required', [rule(names=['settings'])], 'team-a')
    fixed = contract([clause('required', 'must_allow', names=['settings']), clause('forbidden', 'must_not_grant', resource='secrets')], [])
    ops_patch = grant('ops-patch', [rule(('',), ['pods'], ['patch'], ['settings'])], 'team-b', subject='ops')
    ops_create = grant('ops-create', [rule(('',), ['pods'], ['create'], ['settings'])], 'team-b', subject='ops')
    want = dict(kind='pods', operation='apply-missing', user='ops')
    for version in [7, 8]:
        add('v'+str(version)+'-unmentioned-apply-missing', contract(version=7) if version == 7 else fixed,
            common+ops_patch+ops_create[:1], 'proved', baseline=common+ops_patch+ops_create,
            comparison='proved' if version == 7 else 'violated', preservation=want if version == 8 else None)
    for label, change in [('patch', scope(resource='pods', operation='patch', namespace='team-b', subject='ops')),
                          ('apply-existing', scope(resource='pods', operation='apply-existing', namespace='team-b', subject='ops')),
                          ('other-name', scope(resource='pods', operation='apply-missing', namespace='team-b', names=['other'], subject='ops')),
                          ('other-identity', scope(resource='pods', operation='apply-missing', namespace='team-b', subject='app'))]:
        allowed = copy.deepcopy(fixed)
        allowed['change_scope'] = [change]
        add('preserve-missing-outside-'+label, allowed, common+ops_patch+ops_create[:1], 'proved',
            baseline=common+ops_patch+ops_create, comparison='violated', preservation=want)
    # Removing only named create without any patch grant changes no modeled
    # complete operation (collection-create still has empty name).
    add('no-intermediate-grant-preservation-promise', fixed, common+ops_create[:1], 'proved', baseline=common+ops_create, comparison='proved')
    # A patch-only approved scope cannot excuse loss of its SSA-existing sibling.
    restricted = copy.deepcopy(fixed)
    restricted['change_scope'] = [scope(resource='pods', operation='patch', namespace='team-b', subject='ops')]
    add('patch-scope-does-not-cover-existing', restricted, common+ops_patch[:1], 'proved', baseline=common+ops_patch,
        comparison='violated', preservation=dict(kind='pods', operation='apply-existing', user='ops'))
    restricted = copy.deepcopy(fixed)
    restricted['change_scope'] = [scope(resource='pods', operation='apply-existing', namespace='team-b', subject='ops')]
    add('existing-scope-does-not-cover-patch', restricted, common+ops_patch[:1], 'proved', baseline=common+ops_patch,
        comparison='violated', preservation=dict(kind='pods', operation='patch', user='ops'))
    for group, resource, subresource, operation, namespace in [('', 'pods', 'exec', 'create', 'team-b'),
            ('apps', 'deployments', 'scale', 'update', 'team-b'), ('', 'nodes', 'status', 'patch', None),
            ('discovery.k8s.io', 'endpointslices', '', 'deletecollection', 'team-b')]:
        extra = grant('legacy-extra', [rule((group,), [resource+('/'+subresource if subresource else '')], [operation])], namespace, subject='ops')
        kind = resource+('/'+subresource if subresource else '')+('.'+group if group else '')
        add('preserve-legacy-'+resource+'-'+subresource+'-'+operation, fixed, common+extra[:1], 'proved', baseline=common+extra,
            comparison='violated', preservation=dict(kind=kind, operation=operation, user='ops'))
    return cases


def validate_request(row, identities=IDENTITIES, version=8):
    require(type(version) is int and version in [7, 8], 'Unexpected contract version')
    require(isinstance(row, dict) and set(row) == {'id', 'username', 'groups', 'operation', 'apiGroup', 'resource', 'namespace', 'name', 'resourceRequest', 'subresource'}, 'Unexpected operation request schema')
    if row['operation'] not in NEW_OPERATIONS:
        legacy.validate_request(old_row(row), identities, version=7)
        return
    require(version == 8, 'Legacy profile does not admit SSA operations')
    # Reuse only the already frozen named-patch identity and coordinate domain.
    patched = old_row(row)
    patched['verb'] = 'patch'
    require(row['subresource'] == '', 'SSA subresources remain excluded')
    legacy.validate_request(patched, identities, version=7)


def scope_matches(selected, row):
    if 'operation' not in selected:
        return row['operation'] not in NEW_OPERATIONS and legacy.scope_matches(selected, old_row(row))
    changed = dict(selected)
    changed['verb'] = changed.pop('operation')
    return legacy.scope_matches(changed, old_row(row))


def expected_attributes(row, verb, native_http):
    path = ''
    if native_http:
        path = '/apis/'+row['apiGroup']+'/v1' if row['apiGroup'] else '/api/v1'
        path += ('/namespaces/'+row['namespace'] if row['namespace'] else '')+'/'+row['resource']+'/'+row['name']
    return dict(username=row['username'], groups=row['groups'], verb=verb, apiGroup=row['apiGroup'], apiVersion='v1',
        resource=row['resource'], namespace=row['namespace'], name=row['name'], subresource=row['subresource'], resourceRequest=True, path=path)


def audit_native(execution, rows, expected=None):
    require(type(execution.get('returncode')) is int and execution['returncode'] == 0, 'Native reference execution failed')
    result = execution.get('data')
    require(isinstance(result, dict) and set(result) == {'schema_version', 'kind', 'valid', 'validation_errors', 'decisions'}, 'Wrong native result shape')
    require(type(result['schema_version']) is int and result['schema_version'] == 1 and result['kind'] == 'rbac_apply_authorization'
        and result['valid'] is True and result['validation_errors'] == [], 'Invalid native result')
    require(isinstance(result['decisions'], list) and len(result['decisions']) == len(rows), 'Missing native decisions')
    by_id = {r['id']: r for r in rows}
    require(len(by_id) == len(rows), 'Duplicate requested id')
    observed = {}
    for entry in result['decisions']:
        require(isinstance(entry, dict) and set(entry) == {'id', 'decision', 'reason', 'error', 'stages', 'http_status', 'handler_entered', 'storage_reads'}, 'Wrong native decision shape')
        require(entry['id'] in by_id and entry['id'] not in observed, 'Missing/duplicate native id')
        row = by_id[entry['id']]
        require(entry['decision'] in ['Allow', 'NoOpinion'] and entry['error'] == '' and isinstance(entry['reason'], str), 'Native error is not NoOpinion')
        stages = entry['stages']
        require(isinstance(stages, list) and len(stages) in [1, 2], 'Wrong stage count')
        is_apply = row['operation'] in NEW_OPERATIONS
        first_allow = stages[0].get('decision') == 'Allow'
        count = 2 if row['operation'] == 'apply-missing' and first_allow else 1
        require(len(stages) == count, 'Wrong conditional authorization branch')
        for i, stage in enumerate(stages):
            require(isinstance(stage, dict) and set(stage) == {'attributes', 'decision', 'reason', 'error'}, 'Wrong native stage shape')
            verb = ('patch' if i == 0 else 'create') if is_apply else row['operation']
            require(encoded(stage['attributes']) == encoded(expected_attributes(row, verb, is_apply)), 'Native full attributes differ')
            require(stage['decision'] in ['Allow', 'NoOpinion'] and stage['error'] == '' and isinstance(stage['reason'], str), 'Native stage contains a failure')
        outcome = 'Allow' if all(s['decision'] == 'Allow' for s in stages) else 'NoOpinion'
        require(entry['decision'] == outcome, 'Native outcome contradicts observed stages')
        require(type(entry['handler_entered']) is bool and type(entry['storage_reads']) is int and type(entry['http_status']) is int, 'Invalid native control types')
        require(entry['handler_entered'] is (is_apply and first_allow) and entry['storage_reads'] == int(is_apply and first_allow), 'Native handler/storage control differs')
        status = (201 if row['operation'] == 'apply-missing' else 200) if outcome == 'Allow' else 403
        require(entry['http_status'] == (status if is_apply else 0), 'Unexpected native HTTP outcome')
        if expected is not None:
            require(dict(decision=outcome, stages=[s['decision'] for s in stages]) == expected[entry['id']], 'Frozen native grant/stage expectation differs')
        observed[entry['id']] = outcome
    require(set(observed) == set(by_id), 'Native id inventory incomplete')
    return observed


def witness_request(report, spec):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'}, 'Invalid typed witness')
    require(isinstance(obj['resource_kind'], str) and obj['resource_kind'] in KINDS, 'Unknown resource discriminator')
    group, resource, subresource, _ = KINDS[obj['resource_kind']]
    row = dict(id='witness', username=witness.get('principal'), groups=witness.get('identity_groups'), operation=witness.get('action'),
        apiGroup=group, resource=resource, subresource=subresource, namespace=obj['namespace'], name=obj['name'], resourceRequest=True)
    validate_request(row, {i['username']: i['groups'] for i in spec['context']['identities']}, spec['schema_version'])
    require(strings(witness.get('granting_rules'), nonempty=True) and len(set(witness['granting_rules'])) == len(witness['granting_rules']), 'Invalid witness grants')
    if row['operation'] in NEW_OPERATIONS:
        grants = witness['granting_rules']
        for grant_id in grants:
            prefix = next((p for p in ['patch: ', 'create: '] if grant_id.startswith(p)), None)
            require(prefix is not None and len(grant_id) > len(prefix), 'Missing SSA grant-stage attribution')
            require(row['operation'] == 'apply-missing' or prefix == 'patch: ', 'Unexpected create evidence for existing apply')
        if grants:
            require(any(g.startswith('patch: ') for g in grants), 'SSA allowance lacks patch evidence')
            require(row['operation'] != 'apply-missing' or any(g.startswith('create: ') for g in grants), 'SSA allowance lacks create evidence')
    return row


def audit_report(execution, spec, expected, comparison=False):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected and type(execution.get('returncode')) is int and execution['returncode'] == EXIT_CODES[expected], 'Unexpected report verdict/exit')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Wrong report schema')
    require(report.get('property') == ('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'), 'Wrong property')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == (PROFILE if spec['schema_version'] == 8 else legacy.PROFILE)
        and assurance.get('status') == 'within_profile' and assurance.get('findings') == [], 'Wrong assurance')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and frozen['schema_version'] == spec['schema_version']
        and frozen.get('kind') == spec['kind'] and isinstance(frozen.get('canonical'), str), 'Missing frozen spec identity')
    require(encoded(normalized(strict_json(frozen['canonical']))) == encoded(normalized(spec)), 'Frozen contract was changed')
    if expected != 'violated': require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'proved': require(report.get('clause') is None, 'Proof contains a failed clause')
    return report


def audit_witness(report, case, comparison=False):
    row, spec = witness_request(report, case['contract']), case['contract']
    reported = report.get('clause')
    require(isinstance(reported, dict), 'Missing clause identity')
    if comparison:
        require(reported.get('kind') == 'must_preserve' and reported.get('name') == 'preservation-outside-change-scope', 'Wrong preservation obligation')
        require(not any(scope_matches(s, row) for s in spec['change_scope']), 'Witness inside approved changes')
        wanted = case['preservation']
        require(report['counterexample']['object_request']['resource_kind'] == wanted['kind'] and row['operation'] == wanted['operation'] and row['username'] == wanted['user'], 'Wrong preservation witness dimensions')
    else:
        selected = [c for c in spec['clauses'] if c['name'] == reported.get('name')]
        require(len(selected) == 1 and selected[0]['name'] == case['failed'] and selected[0]['kind'] == reported.get('kind') and scope_matches(selected[0], row), 'Witness outside expected clause')
    return row


def rejection_requests():
    rows = []
    for group, resource, namespaced in resources.CATALOGUE:
        base = request(group, resource, namespace='team-a' if namespaced else '')
        for label, change in [('empty-name', dict(name='')), ('wrong-namespace', dict(namespace='' if namespaced else 'team-a')),
                              ('put-create', dict(operation='update-missing')), ('status', dict(subresource='status'))]:
            rows.append(dict(base, id=resource+'-'+label, **change))
    base = request()
    for label, change in [('literal-star', dict(name='*')), ('uppercase-name', dict(name='UPPER')), ('wrong-group', dict(apiGroup='apps')),
        ('unknown-identity', dict(username='stranger')), ('wrong-groups', dict(groups=['operators'])), ('nonresource', dict(resourceRequest=False)),
        ('api-version', dict(apiVersion='v1')), ('old-verb-field', dict(verb='patch'))]:
        rows.append(dict(base, id=label, **change))
    return rows


def planned_inputs():
    inputs = {'contract.json': encoded(contract()), 'legacy-contract.json': encoded(contract(version=7)),
        'catalogue.json': encoded(CATALOGUE), 'matrix/requests.json': encoded(matrix_requests()),
        'rejections/requests.json': encoded(rejection_requests()), 'native-linkage.json': encoded(LINKAGE)}
    for case in matrix_cases():
        for key in ['snapshot', 'expected']: inputs['matrix/'+case['id']+'/'+key+'.json'] = encoded(case[key])
    for case in contract_cases():
        for key in ['contract', 'snapshot', 'baseline']:
            if case[key] is not None: inputs['contracts/'+case['id']+'/'+key+'.json'] = encoded(case[key])
        inputs['contracts/'+case['id']+'/expected.json'] = encoded({k: case[k] for k in ['expected', 'failed', 'comparison', 'preservation']})
    return inputs


def source_provenance(module_metadata):
    metadata = read_json(module_metadata)
    roots = {'kubernetes': Path(metadata['Dir']), 'apiserver': Path(metadata['Dir']).parent/'apiserver@v0.34.0'}
    pins = read_json(HERE/'source-pins.json')
    require(isinstance(pins, dict) and set(pins) == set(SOURCE_FILES), 'Wrong source module inventory')
    result = {}
    for module, entries in pins.items():
        require(isinstance(entries, dict) and set(entries) == set(SOURCE_FILES[module]), 'Missing/extra pinned module sources')
        for relative, sha in entries.items():
            require(isinstance(relative, str) and not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Unsafe source path')
            path = roots[module]/relative
            require(isinstance(sha, str) and digest(path) == sha, 'Pinned upstream source differs: '+str(path))
            result[str(path)] = sha
    return result


def finite_requests(spec):
    return [r for r in matrix_requests() if spec['schema_version'] == 8 or r['operation'] not in NEW_OPERATIONS]


def planned_counts(native_only=False):
    cases = contract_cases()
    return dict(matrix_comparisons=len(matrix_requests())*len(matrix_cases()),
        contract_native_checks=sum(len(finite_requests(c['contract']))*(2 if c['baseline'] is not None else 1) for c in cases),
        rejected_requests=0 if native_only else len(rejection_requests()),
        legacy_rejected_requests=0 if native_only else sum(r['operation'] in NEW_OPERATIONS for r in matrix_requests()),
        contract_witness_replays=0 if native_only else sum(c['expected'] == 'violated' for c in cases),
        preservation_witness_replays=0 if native_only else sum(c['comparison'] == 'violated' for c in cases))


def audit_completion(result, native_only=False):
    require(result.get('failures') == [], 'Cannot complete failed evidence')
    for key, expected in planned_counts(native_only).items():
        require(type(result.get(key)) is int and result[key] == expected, 'Incomplete/invalid counter: '+key)
    require(result.get('native_only') is native_only, 'Wrong execution mode')
    expected_cases = {'matrix/'+case['id']: dict(matrix_comparisons=len(matrix_requests())) for case in matrix_cases()}
    for case in contract_cases():
        entry = dict(native_contract=case['expected'], native_comparison=case['comparison'])
        if not native_only:
            entry['contract'] = case['expected']
            if case['baseline'] is not None: entry['comparison'] = case['comparison']
        expected_cases['contracts/'+case['id']] = entry
    require(encoded(result.get('cases')) == encoded(expected_cases), 'Missing/altered completed case inventory')
    require(result.get('inputs_unchanged') is True and result.get('binaries_unchanged') is True, 'Unverified provenance stability')
    require(result.get('native_linkage_verified') is True, 'Native runtime/source linkage not verified')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'module-metadata', 'output']: parser.add_argument('--'+name, type=Path, required=True)
    for name in ['model', 'soundcheck']: parser.add_argument('--'+name, type=Path)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        if isinstance(value, Path): setattr(args, key, value.resolve())
    result = dict(complete=False, profile=PROFILE, native_only=args.native_only, cases={}, failures=[], input_sha256={},
        **{key: 0 for key in planned_counts()}, limits=[
            'Frozen synthetic authorization branches, not a deployed-cluster benchmark or inference of live object existence.',
            'SSA uses native authorization filter, PATCH handler, field manager, resource strategies and generic store with in-memory Get and native dryRun=All.',
            'Fixtures force field ownership only to isolate authorization; admission, object effects, storage races and field conflicts are outside the profile.',
            'Only eight base resources gain SSA; schema7 initial classes retain their existing meaning.',
            'Native NoOpinion is not a final denial from arbitrary authorization chains.',
            'Finite native/concrete/SMT agreement and witness replay are not a universal proof of implementation correctness.'])
    save(args.output, result)
    try:
        result['reference'] = module_provenance(args.module_metadata)
        result['upstream_source_sha256'] = source_provenance(args.module_metadata)
        inputs = planned_inputs()
        audit_pins(inputs, read_json(HERE/'inputs.json'))
        require((HERE/'contract.json').read_bytes() == inputs['contract.json'], 'Runnable contract differs from frozen fixture')
        artifacts = args.output.parent/'artifacts'
        for key, value in inputs.items():
            path = artifacts/key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            result['input_sha256'][str(path)] = digest(path)
        source_dir = Path(__file__).resolve().parent
        result['source_sha256'] = {str(path): digest(path) for path in [Path(__file__), HERE/'generate.py', HERE/'inputs.json', HERE/'contract.json', HERE/'source-pins.json', args.module_metadata, source_dir/'test_apply_runner.py']+
            [source_dir/name for name in ['run.py', 'run_scopes.py', 'run_write_access.py', 'run_read_access.py', 'run_resources.py', 'run_collection_writes.py', 'run_subresources.py', 'oracle/go.mod', 'oracle/go.sum', 'oracle/module-pins.json']]+
            sorted((source_dir/'oracle').glob('*.go'))}
        binaries, z3 = [args.reference], None
        if not args.native_only:
            require(args.model is not None and args.soundcheck is not None, 'Production comparison needs model and soundcheck')
            z3 = shutil.which(args.z3)
            require(z3 is not None, 'Z3 is required')
            binaries += [args.model, args.soundcheck, Path(z3)]
        result['binary_sha256'] = {str(path): digest(path) for path in binaries}
        save(args.output.parent/'before-execution.json', result)
        save(args.output, result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-apply-z3-') as temporary:
            environment = dict(os.environ)
            if z3 is not None:
                Path(temporary, 'z3').symlink_to(Path(z3).resolve())
                environment['PATH'] = temporary+os.pathsep+environment.get('PATH', '')
            result['native_linkage'] = audit_linkage(execute([args.reference, '--apply-reference-info'], args.output.parent/'native-linkage.json', environment))
            result['native_linkage_verified'] = True
            def native(manifest, rows, folder, label, expected=None):
                path = folder/(label+'-requests.json')
                save(path, rows)
                return audit_native(execute([args.reference, '--apply-reference', manifest, path], folder/(label+'-reference.json'), environment), rows, expected)
            def agree(manifest, spec_path, rows, folder, label, expected=None):
                spec = read_json(spec_path)
                for row in rows: validate_request(row, version=spec['schema_version'])
                upstream = native(manifest, rows, folder, label, expected)
                if not args.native_only:
                    model_rows = rows if spec['schema_version'] == 8 else [old_row(r) for r in rows]
                    path = folder/(label+'-model-requests.json')
                    save(path, model_rows)
                    model = execute([args.model, manifest, spec_path, path], folder/(label+'-model.json'), environment)
                    concrete = decisions(model, model_rows, 'model')
                    symbolic = smt_decisions(model, model_rows, folder, label, z3, environment)
                    require(upstream == concrete == symbolic, 'Native/concrete/SMT mismatch: '+label)
                return upstream
            rows = matrix_requests()
            for case in matrix_cases():
                folder = artifacts/'matrix'/case['id']
                agree(folder/'snapshot.json', artifacts/'contract.json', rows, folder, 'matrix', case['expected'])
                result['matrix_comparisons'] += len(rows)
                result['cases']['matrix/'+case['id']] = dict(matrix_comparisons=len(rows))
                print(case['id']+': native stages and frozen expectations agree', flush=True)
                save(args.output, result)
            for case in contract_cases():
                folder = artifacts/'contracts'/case['id']
                manifest, spec_path, spec = folder/'snapshot.json', folder/'contract.json', case['contract']
                finite = finite_requests(spec)
                observed = native(manifest, finite, folder, 'finite')
                failed = []
                for selected in spec['clauses']:
                    points = [r for r in finite if scope_matches(selected, r)]
                    require(points, 'Finite corpus does not inhabit clause '+selected['name'])
                    wanted = 'Allow' if selected['kind'] == 'must_allow' else 'NoOpinion'
                    if any(observed[r['id']] != wanted for r in points): failed.append(selected['name'])
                require(bool(failed) == (case['expected'] == 'violated'), 'Native contract differs: '+case['id'])
                if failed: require(failed[0] == case['failed'], 'Unexpected first native failing clause')
                result['contract_native_checks'] += len(finite)
                if case['baseline'] is not None:
                    prior = native(folder/'baseline.json', finite, folder, 'finite-before')
                    changed = [r for r in finite if prior[r['id']] != observed[r['id']] and not any(scope_matches(s, r) for s in spec['change_scope'])]
                    require(bool(changed) == (case['comparison'] == 'violated'), 'Native preservation differs: '+case['id'])
                    result['contract_native_checks'] += len(finite)
                def replay(report, comparison=False):
                    row = audit_witness(report, case, comparison)
                    after = agree(manifest, spec_path, [row], folder, 'witness-after')['witness']
                    require(bool(report['counterexample']['granting_rules']) == (after == 'Allow'), 'Witness grants contradict native decision')
                    if comparison:
                        before = agree(folder/'baseline.json', spec_path, [row], folder, 'witness-before')['witness']
                        require(before != after, 'Preservation witness has no native decision change')
                        result['preservation_witness_replays'] += 1
                    else:
                        require(after == ('Allow' if report['clause']['kind'] == 'must_not_grant' else 'NoOpinion'), 'Native decision does not violate clause')
                        result['contract_witness_replays'] += 1
                entry = dict(native_contract=case['expected'], native_comparison=case['comparison'])
                if not args.native_only:
                    report = audit_report(execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', spec_path, '--format', 'json'], folder/'verify.json', environment), spec, case['expected'])
                    entry['contract'] = report['result']
                    if report['result'] == 'violated': replay(report)
                    if case['baseline'] is not None:
                        compared = audit_report(execute([args.soundcheck, 'rbac', 'compare', folder/'baseline.json', manifest, '--contract', spec_path, '--format', 'json'], folder/'compare.json', environment), spec, case['comparison'], True)
                        entry['comparison'] = compared['result']
                        if compared['result'] == 'violated': replay(compared, True)
                result['cases']['contracts/'+case['id']] = entry
                print(case['id']+': native contract/preservation checked', flush=True)
                save(args.output, result)
            if not args.native_only:
                def reject(row, spec_path, label):
                    path = artifacts/'rejections'/(label+'.json')
                    save(path, [row])
                    model = execute([args.model, artifacts/'matrix/whole-wildcards/snapshot.json', spec_path, path], artifacts/'rejections'/(label+'-model.json'), environment)
                    require(decisions(model, [row], 'model', allow_unsupported=True) is None, 'Outside-domain request received a decision: '+label)
                for row in rejection_requests():
                    reject(row, artifacts/'contract.json', row['id'])
                    result['rejected_requests'] += 1
                for row in rows:
                    if row['operation'] in NEW_OPERATIONS:
                        reject(old_row(row), artifacts/'legacy-contract.json', 'v7-'+row['id'])
                        result['legacy_rejected_requests'] += 1
            for key in ['input_sha256', 'source_sha256', 'binary_sha256', 'upstream_source_sha256']:
                require(all(digest(Path(path)) == sha for path, sha in result[key].items()), key+' changed during execution')
            audit_pins(planned_inputs(), read_json(HERE/'inputs.json'))
            result.update(inputs_unchanged=True, binaries_unchanged=True)
            audit_completion(result, args.native_only)
            result['complete'] = True
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result['failures'].append(str(error))
    save(args.output, result)
    print({key: result[key] for key in ['complete', 'native_only']+list(planned_counts())+['failures']})
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
