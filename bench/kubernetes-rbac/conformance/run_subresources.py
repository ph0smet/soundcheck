#!/usr/bin/env python3
"""Independent, frozen schema-7 subresource experiments against Kubernetes1.34.0.

Only initial RBAC attributes and decisions are compared. Installed operations
are an explicit source-derived catalogue, never inferred from wildcard grants.
--native-only establishes reference evidence before production is consulted.
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
import run_collection_writes as collections
import run_resources as resources
from run_resources import (IDENTITIES, rule, grant, snapshot, encoded, byte_hash,
                           audit_pins)

HERE = Path(__file__).resolve().parent.parent/'subresources'
PROFILE = 'kubernetes-rbac-v1.34-subresources-v1'
LEGACY_PROFILE = collections.PROFILE
# HTTP methods come from pinned installed handlers, not from RBAC's permissive
# handling of arbitrary attribute records. The group remains the request group.
CATALOGUE = [
    ('', 'pods', 'log', True, [('GET', 'get')]),
    ('', 'pods', 'exec', True, [('GET', 'get'), ('POST', 'create')]),
    ('', 'serviceaccounts', 'token', True, [('POST', 'create')]),
    ('', 'pods', 'status', True, [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch')]),
    ('', 'services', 'status', True, [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch')]),
    ('', 'nodes', 'status', False, [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch')]),
    ('apps', 'deployments', 'status', True, [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch')]),
    ('apps', 'deployments', 'scale', True, [('GET', 'get'), ('PUT', 'update'), ('PATCH', 'patch')]),
]
KINDS = {kind: (g, r, '', ns) for kind, (g, r, ns) in resources.KINDS.items()}
KINDS.update({r+'/'+s+('.'+g if g else ''): (g, r, s, ns) for g, r, s, ns, _ in CATALOGUE})
SOURCE_FILES = {
    'kubernetes': ['plugin/pkg/auth/authorizer/rbac/rbac.go', 'pkg/apis/rbac/v1/evaluation_helpers.go',
        'pkg/registry/core/pod/rest/log.go', 'pkg/registry/core/pod/rest/subresources.go',
        'pkg/registry/core/pod/storage/storage.go', 'pkg/registry/core/service/storage/storage.go',
        'pkg/registry/core/node/storage/storage.go', 'pkg/registry/core/serviceaccount/storage/token.go',
        'pkg/registry/apps/deployment/storage/storage.go', 'pkg/registry/core/rest/storage_core_generic.go',
        'pkg/registry/apps/rest/storage_apps.go', 'plugin/pkg/admission/noderestriction/admission.go'],
    'apiserver': ['pkg/endpoints/request/requestinfo.go', 'pkg/endpoints/filters/authorization.go',
        'pkg/endpoints/installer.go', 'pkg/endpoints/handlers/get.go', 'pkg/endpoints/handlers/rest.go',
        'pkg/endpoints/handlers/create.go'],
}


def scope(resource='configmaps', group='', subresource='', verb='get', namespace='team-a', names=None, subject='app'):
    return dict(resources.scope(resource, group, verb, namespace, names, subject), subresource=subresource)


def clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **scope(**kwargs))


def contract(clauses=None, changes=None, version=7):
    if version == 6:
        return collections.contract(resources.contract()['clauses'], [], version=6)
    if clauses is None:
        clauses = [clause('required-log', 'must_allow', resource='pods', subresource='log', names=['settings']),
                   clause('forbidden-exec', 'must_not_grant', resource='pods', subresource='exec', verb='create')]
    if changes is None:
        changes = [scope(resource='pods', subresource='exec', verb='create')]
    return resources.contract(clauses, changes, version=version)


def request(group, resource, subresource='', verb='get', namespace='team-a', name='settings', user='app', id_='request'):
    return dict(resources.request(group, resource, verb, namespace, name, user, id_), subresource=subresource)


def matrix_requests():
    rows = collections.matrix_requests()
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        for _, verb in operations:
            for namespace in ['team-a', 'team-b'] if namespaced else ['']:
                for name in ['settings', 'other']:
                    for user in IDENTITIES:
                        rows.append(request(group, resource, subresource, verb, namespace, name, user, str(len(rows))))
    return rows


def matrix_cases():
    rows, cases = matrix_requests(), []
    def add(id_, items, allowed):
        cases.append(dict(id=id_, snapshot=snapshot(items),
                          expected={r['id']: 'Allow' if allowed(r) else 'NoOpinion' for r in rows}))
    app = lambda r: r['username'] == 'app'
    sub = lambda r: app(r) and bool(r['subresource'])
    any_rule = rule(('*',), ('*',), ['*'])
    add('empty-policy', [], lambda _: False)
    add('whole-wildcards', grant('all', [any_rule]), app)
    add('namespaced-role', grant('local', [any_rule], 'team-a', local_role=True), lambda r: app(r) and r['namespace'] == 'team-a')
    add('rolebinding-clusterrole', grant('bound', [any_rule], 'team-a'), lambda r: app(r) and r['namespace'] == 'team-a')
    add('base-resources-only', grant('base', [rule(('*',), [r for _, r, _ in resources.CATALOGUE], ['*'])]),
        lambda r: app(r) and r['subresource'] == '')
    add('parent-star-is-literal', grant('parent-star', [rule(('*',), ['pods/*', 'nodes/*', 'services/*', 'deployments/*', 'serviceaccounts/*', '*/*'], ['*'])]), lambda _: False)
    add('qualified-and-singular-literals', grant('literal', [rule(('*',), ['pod/exec', 'deployments/scale.apps', 'pods/Exec'], ['*'])]), lambda _: False)
    add('connect-is-not-rbac-verb', grant('connect', [rule(('*',), ('*',), ['connect'])]), lambda _: False)
    for subresource in ['log', 'exec', 'token', 'status', 'scale']:
        add('star-'+subresource, grant('star-'+subresource, [rule(('*',), ['*/'+subresource], ['*'])]),
            lambda r, s=subresource: sub(r) and r['subresource'] == s)
    for verb in ['get', 'create', 'update', 'patch']:
        add(verb+'-subresources', grant(verb, [rule(('*',), ['*/'+s for s in ['log', 'exec', 'token', 'status', 'scale']], [verb])]),
            lambda r, v=verb: sub(r) and r['verb'] == v)
    for group, label in [('', 'core'), ('apps', 'apps')]:
        add(label+'-group', grant(label, [rule((group,), ('*',), ['*'])]), lambda r, g=group: app(r) and r['apiGroup'] == g)
    add('response-groups-do-not-authorize', grant('wrong-groups', [rule(('authentication.k8s.io',), ['serviceaccounts/token'], ['create']),
        rule(('autoscaling',), ['deployments/scale'], ['get', 'update', 'patch'])]), lambda _: False)
    exact = [rule((g,), [r+'/'+s], [v for _, v in operations]) for g, r, s, _, operations in CATALOGUE]
    add('all-exact-installed-operations', grant('exact', exact), sub)
    for names, label in [(None, 'omitted'), ([], 'empty-list'), (['settings'], 'parent'), ([''], 'empty-name'), (['*'], 'literal-star'), (['', 'settings'], 'mixed')]:
        add(label+'-resourceNames', grant(label, [rule(('*',), ('*',), ['*'], names)]),
            lambda r, n=names: app(r) and (not n or r['name'] in n))
    operators = grant('operators', exact)
    operators[1]['subjects'] = [dict(kind='Group', apiGroup=resources.API, name='operators')]
    add('trusted-group-subresources', operators, lambda r: r['username'] == 'ops' and bool(r['subresource']))
    add('additive-name-bypass', grant('restricted', [rule(('',), ['pods/exec'], ['create'], ['settings'])], 'team-a')+
        grant('bypass', [rule(('',), ['pods/exec'], ['create'])], 'team-b'),
        lambda r: sub(r) and r['resource'] == 'pods' and r['subresource'] == 'exec' and r['verb'] == 'create' and
            (r['namespace'] == 'team-b' or (r['namespace'] == 'team-a' and r['name'] == 'settings')))
    aggregate = grant('aggregate', exact)
    aggregate[0]['aggregationRule'] = dict(clusterRoleSelectors=[dict(matchLabels={'conformance.soundcheck/subresources': 'true'})])
    leaf = grant('leaf', exact)[0]
    leaf['metadata']['labels'] = {'conformance.soundcheck/subresources': 'true'}
    add('resolved-aggregate-subresources', [leaf]+aggregate, sub)
    return cases


def contract_cases():
    cases = []
    def add(id_, spec, items, expected, failed=None, baseline=None, comparison=None, preservation=None):
        cases.append(dict(id=id_, contract=spec, snapshot=snapshot(items), expected=expected, failed=failed,
            baseline=None if baseline is None else snapshot(baseline), comparison=comparison, preservation=preservation))
    logs = grant('logs', [rule(('',), ['pods/log'], ['get'], ['settings'])], 'team-a')
    exe = grant('exec', [rule(('',), ['pods/exec'], ['create'])], 'team-a')
    spec = contract()
    add('unsafe-exec', spec, logs+exe, 'violated', 'forbidden-exec')
    add('minimal-exec-repair', spec, logs+exe[:1], 'proved', baseline=logs+exe, comparison='proved')
    add('lost-log-functionality', spec, logs[:1]+exe[:1], 'violated', 'required-log')
    add('get-exec-is-distinct-from-post', spec, logs+grant('get-exec', [rule(('',), ['pods/exec'], ['get'])], 'team-a'), 'proved')
    add('empty-name-does-not-grant-log', spec, grant('empty-log', [rule(('',), ['pods/log'], ['get'], [''])], 'team-a'), 'violated', 'required-log')
    # Every installed operation has independently fixed paired parent-name intent.
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        for _, verb in operations:
            label = resource+'-'+subresource+'-'+verb
            args = dict(group=group, resource=resource, subresource=subresource, verb=verb, namespace='team-a' if namespaced else None)
            paired = contract([clause('required-parent', 'must_allow', **args, names=['settings']),
                               clause('other-parent', 'must_not_grant', **args, names={'exclude': ['settings'], 'include_empty': False})], [])
            items = grant(label, [rule((group,), [resource+'/'+subresource], [verb], ['settings'])], 'team-a' if namespaced else None)
            add('named-'+label, paired, items, 'proved')
    required = clause('required-log', 'must_allow', resource='pods', subresource='log', names=['settings'], namespace={'include': ['team-b', 'team-a']})
    outside = scope(resource='pods', subresource='exec', verb='create', namespace={'exclude': ['team-a']}, names={'exclude': ['settings'], 'include_empty': False})
    selected = contract([required, dict(name='forbidden-selected-exec', kind='must_not_grant', **outside)], [outside])
    two_logs = logs+grant('logs-b', [rule(('',), ['pods/log'], ['get'], ['settings'])], 'team-b')
    add('namespace-name-selectors', selected, two_logs, 'proved')
    add('selector-leak', selected, two_logs+grant('global-exec', [rule(('',), ['pods/exec'], ['create'])]), 'violated', 'forbidden-selected-exec')
    node_spec = contract([clause('required-node-status', 'must_allow', resource='nodes', subresource='status', verb='patch', namespace=None),
                          clause('forbidden', 'must_not_grant', resource='secrets')], [])
    add('rolebinding-does-not-grant-node-status', node_spec, grant('local-node', [rule(('',), ['nodes/status'], ['patch'])], 'team-a'), 'violated', 'required-node-status')
    common = grant('required-config', [rule(names=['settings'])], 'team-a')
    for group, resource, subresource, verb, namespace in [('', 'pods', 'exec', 'create', 'team-b'),
            ('', 'serviceaccounts', 'token', 'create', 'team-b'), ('', 'nodes', 'status', 'patch', None),
            ('apps', 'deployments', 'scale', 'update', 'team-b')]:
        extra = grant('ops-extra', [rule((group,), [resource+'/'+subresource], [verb])], namespace, subject='ops')
        kind = resource+'/'+subresource+('.'+group if group else '')
        for version in [6, 7]:
            fixed = contract(version=6) if version == 6 else contract([clause('required', 'must_allow', names=['settings']), clause('forbidden', 'must_not_grant', resource='secrets')], [])
            add(f'v{version}-unmentioned-'+resource+'-'+subresource, fixed, common+extra[:1], 'proved', baseline=common+extra,
                comparison='proved' if version == 6 else 'violated', preservation=dict(kind=kind, verb=verb, user='ops'))
    # A change scope never grants permission to alter a sibling subresource,
    # another verb, or the parent resource, even when the verb is also create.
    fixed = contract([clause('required', 'must_allow', names=['settings']), clause('forbidden', 'must_not_grant', resource='secrets')], [])
    extra = grant('ops-exec', [rule(('',), ['pods/exec'], ['create'])], 'team-b', subject='ops')
    for label, change in [('parent-create', scope(resource='pods', verb='create', namespace='team-b', names=None, subject='ops')),
            ('get-exec', scope(resource='pods', subresource='exec', verb='get', namespace='team-b', subject='ops')),
            ('other-parent', scope(resource='pods', subresource='exec', verb='create', namespace='team-b', names=['other'], subject='ops'))]:
        adjusted = copy.deepcopy(fixed)
        adjusted['change_scope'] = [change]
        # Restrict the changed grant for the name-disjoint scope control.
        narrowed = grant('ops-exec', [rule(('',), ['pods/exec'], ['create'], ['settings'])], 'team-b', subject='ops') if label == 'other-parent' else extra
        add('preserve-'+label, adjusted, common+narrowed[:1], 'proved', baseline=common+narrowed, comparison='violated',
            preservation=dict(kind='pods/exec', verb='create', user='ops'))
    # New contracts still preserve all old resources, collection verbs and identities.
    old_extra = grant('ops-bulk', [rule(('discovery.k8s.io',), ['endpointslices'], ['deletecollection'])], 'team-b', subject='ops')
    add('preserve-base-collection-write', fixed, common+old_extra[:1], 'proved', baseline=common+old_extra, comparison='violated',
        preservation=dict(kind='endpointslices.discovery.k8s.io', verb='deletecollection', user='ops'))
    return cases


def validate_request(row, identities=IDENTITIES, version=7):
    require(type(version) is int and version in [6, 7], 'Unexpected campaign contract version')
    if version == 6 or (isinstance(row, dict) and row.get('subresource') == ''):
        collections.validate_request(row, identities, version=6)
        return
    require(isinstance(row, dict) and set(row) == {'id', 'username', 'groups', 'verb', 'apiGroup', 'resource', 'namespace', 'name', 'resourceRequest', 'subresource'}, 'Unexpected request schema')
    require(isinstance(row['id'], str) and row['id'], 'Invalid request id')
    require(isinstance(row['username'], str) and row['username'] in identities, 'Unknown frozen identity')
    require(strings(row['groups'], nonempty=True) and len(set(row['groups'])) == len(row['groups']) and sorted(row['groups']) == sorted(identities[row['username']]), 'Identity groups differ')
    require(row['resourceRequest'] is True, 'Not a resource request')
    entries = [entry for entry in CATALOGUE if entry[:3] == (row['apiGroup'], row['resource'], row['subresource'])]
    require(len(entries) == 1 and row['verb'] in [v for _, v in entries[0][4]], 'Outside installed operation catalogue')
    require(valid_dns(row['namespace'], 63, DNS_LABEL) if entries[0][3] else row['namespace'] == '', 'Invalid subresource namespace')
    require(valid_dns(row['name'], 253, DNS_SUBDOMAIN), 'Subresource requires a named parent')


def scope_matches(selected, row):
    return selected.get('subresource', '') == row['subresource'] and resources.scope_matches(selected, row)


def witness_request(report, spec):
    witness = report.get('counterexample')
    require(isinstance(witness, dict), 'Missing counterexample')
    obj = witness.get('object_request')
    require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'}, 'Invalid typed witness')
    require(isinstance(obj['resource_kind'], str) and obj['resource_kind'] in KINDS, 'Unknown resource discriminator')
    group, resource, subresource, _ = KINDS[obj['resource_kind']]
    row = dict(id='witness', username=witness.get('principal'), groups=witness.get('identity_groups'), verb=witness.get('action'),
        apiGroup=group, resource=resource, subresource=subresource, namespace=obj['namespace'], name=obj['name'], resourceRequest=True)
    validate_request(row, {i['username']: i['groups'] for i in spec['context']['identities']}, spec['schema_version'])
    require(strings(witness.get('granting_rules'), nonempty=True) and len(set(witness['granting_rules'])) == len(witness['granting_rules']), 'Invalid witness grants')
    return row


def audit_report(execution, spec, expected, comparison=False):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected and type(execution.get('returncode')) is int and execution['returncode'] == EXIT_CODES[expected], 'Unexpected report verdict/exit')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Wrong report schema')
    require(report.get('property') == ('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'), 'Wrong property')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == (PROFILE if spec['schema_version'] == 7 else LEGACY_PROFILE)
        and assurance.get('status') == 'within_profile' and assurance.get('findings') == [], 'Wrong assurance')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and frozen['schema_version'] == spec['schema_version']
        and frozen.get('kind') == spec['kind'] and isinstance(frozen.get('canonical'), str), 'Missing frozen spec identity')
    require(encoded(normalized(strict_json(frozen['canonical']))) == encoded(normalized(spec)), 'Frozen contract was changed')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'proved':
        require(report.get('clause') is None, 'Proof contains a failed clause')
    return report


def audit_witness(report, case, comparison=False):
    row, spec = witness_request(report, case['contract']), case['contract']
    reported = report.get('clause')
    require(isinstance(reported, dict), 'Missing clause identity')
    if comparison:
        require(reported.get('kind') == 'must_preserve' and reported.get('name') == 'preservation-outside-change-scope', 'Wrong preservation obligation')
        require(not any(scope_matches(s, row) for s in spec['change_scope']), 'Witness inside approved changes')
        wanted = case['preservation']
        require(report['counterexample']['object_request']['resource_kind'] == wanted['kind'] and row['verb'] == wanted['verb'] and row['username'] == wanted['user'], 'Wrong preservation witness dimensions')
    else:
        selected = [c for c in spec['clauses'] if c['name'] == reported.get('name')]
        require(len(selected) == 1 and selected[0]['name'] == case['failed'] and selected[0]['kind'] == reported.get('kind') and scope_matches(selected[0], row), 'Witness outside expected clause')
    return row


def url_cases():
    rows = []
    def add(id_, method, path, group, resource, subresource, verb, namespace, name, supported=True, body=None):
        incoming = dict(id=id_, username='app', groups=[], method=method, url=path)
        if body is not None:
            incoming['body'] = body
        attrs = request(group, resource, subresource, verb, namespace, name)
        del attrs['id']
        attrs.update(apiVersion='v1', path=path.split('?', 1)[0])
        rows.append(dict(request=incoming, attributes=attrs, supported=supported, field_selector_error=False, label_selector_error=False))
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        prefix = '/apis/'+group+'/v1' if group else '/api/v1'
        namespace = 'team-a' if namespaced else ''
        base = prefix+('/namespaces/'+namespace if namespaced else '')+'/'+resource
        for method, verb in operations:
            label = resource+'-'+subresource+'-'+verb
            path = base+'/settings/'+subresource
            add(label, method, path, group, resource, subresource, verb, namespace, 'settings')
            add(label+'-other-parent', method, base+'/other/'+subresource, group, resource, subresource, verb, namespace, 'other')
            if namespaced:
                add(label+'-other-namespace', method, path.replace('team-a', 'team-b'), group, resource, subresource, verb, 'team-b', 'settings')
            if method == 'GET':
                add(label+'-query', method, path+'?watch=true&follow=true&fieldSelector=metadata.name%3Dother&name=other', group, resource, subresource, verb, namespace, 'settings')
            else:
                for suffix, body in [('body-name', '{"metadata":{"name":"other","namespace":"team-b"}}'), ('malformed-body', '{broken')]:
                    add(label+'-'+suffix, method, path, group, resource, subresource, verb, namespace, 'settings', body=body)
    add('fabricated-pods-scale', 'GET', '/api/v1/namespaces/team-a/pods/settings/scale', '', 'pods', 'scale', 'get', 'team-a', 'settings', False)
    add('log-post-not-installed', 'POST', '/api/v1/namespaces/team-a/pods/settings/log', '', 'pods', 'log', 'create', 'team-a', 'settings', False)
    add('status-delete-not-installed', 'DELETE', '/api/v1/namespaces/team-a/pods/settings/status', '', 'pods', 'status', 'delete', 'team-a', 'settings', False)
    add('scale-post-not-installed', 'POST', '/apis/apps/v1/namespaces/team-a/deployments/settings/scale', 'apps', 'deployments', 'scale', 'create', 'team-a', 'settings', False)
    add('token-get-not-installed', 'GET', '/api/v1/namespaces/team-a/serviceaccounts/settings/token', '', 'serviceaccounts', 'token', 'get', 'team-a', 'settings', False)
    add('token-response-group', 'POST', '/apis/authentication.k8s.io/v1/namespaces/team-a/serviceaccounts/settings/token', 'authentication.k8s.io', 'serviceaccounts', 'token', 'create', 'team-a', 'settings', False)
    add('scale-response-group', 'PATCH', '/apis/autoscaling/v1/namespaces/team-a/deployments/settings/scale', 'autoscaling', 'deployments', 'scale', 'patch', 'team-a', 'settings', False)
    add('node-status-namespaced', 'PATCH', '/api/v1/namespaces/team-a/nodes/settings/status', '', 'nodes', 'status', 'patch', 'team-a', 'settings', False)
    add('exec-namespace-missing', 'POST', '/api/v1/pods/settings/exec', '', 'pods', 'exec', 'create', '', 'settings', False)
    # Retain the crucial contrast: top-level POST has no authorization name.
    add('base-create-body-name', 'POST', '/api/v1/namespaces/team-a/pods', '', 'pods', '', 'create', 'team-a', '', body='{"metadata":{"name":"settings"}}')
    add('base-named-create-excluded', 'POST', '/api/v1/namespaces/team-a/pods/settings', '', 'pods', '', 'create', 'team-a', 'settings', False)
    return rows


def url_policies():
    return [('unrestricted', None, None), ('named', ['settings'], None), ('empty', [''], None), ('literal-star', ['*'], None), ('rolebinding', None, 'team-a')]


def url_expected(names, namespace=None):
    return [dict(row, decision='Allow' if (names is None or row['attributes']['name'] in names) and
            (namespace is None or row['attributes']['namespace'] == namespace) else 'NoOpinion') for row in url_cases()]


def audit_urls(execution, expected):
    require(type(execution.get('returncode')) is int, 'Invalid native URL exit status')
    return collections.audit_urls(execution, expected)


def rejection_requests():
    result = []
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        permitted = [verb for _, verb in operations]
        for verb in collections.VERBS+['connect']:
            if verb not in permitted:
                result.append(request(group, resource, subresource, verb, 'team-a' if namespaced else '', id_='forbidden-'+resource+'-'+subresource+'-'+verb))
        for label, change in [('empty-parent', dict(name='')), ('star-parent', dict(name='*')), ('uppercase-parent', dict(name='UPPER')),
                              ('wrong-namespace', dict(namespace='' if namespaced else 'team-a'))]:
            row = request(group, resource, subresource, permitted[0], 'team-a' if namespaced else '', id_=label+'-'+resource+'-'+subresource)
            result.append(dict(row, **change))
    base = request('', 'pods', 'exec', 'create')
    for label, change in [('fabricated', dict(subresource='scale')), ('combined-resource', dict(resource='pods/exec', subresource='')),
        ('wrong-group', dict(apiGroup='apps')), ('nonresource', dict(resourceRequest=False)), ('unknown-subresource', dict(subresource='attach')),
        ('unknown-identity', dict(username='stranger')), ('wrong-groups', dict(groups=['operators']))]:
        result.append(dict(base, id=label, **change))
    return result


def planned_inputs():
    inputs = {'contract.json': encoded(contract()), 'legacy-contract.json': encoded(contract(version=6)),
              'catalogue.json': encoded(CATALOGUE), 'matrix/requests.json': encoded(matrix_requests()),
              'rejections/requests.json': encoded(rejection_requests())}
    for case in matrix_cases():
        for key in ['snapshot', 'expected']:
            inputs['matrix/'+case['id']+'/'+key+'.json'] = encoded(case[key])
    for case in contract_cases():
        for key in ['contract', 'snapshot', 'baseline']:
            if case[key] is not None:
                inputs['contracts/'+case['id']+'/'+key+'.json'] = encoded(case[key])
        inputs['contracts/'+case['id']+'/expected.json'] = encoded({k: case[k] for k in ['expected', 'failed', 'comparison', 'preservation']})
    for label, names, namespace in url_policies():
        inputs['urls/'+label+'/snapshot.json'] = encoded(snapshot(grant('url', [rule(('*',), ('*',), ['*'], names)], namespace)))
        inputs['urls/'+label+'/requests.json'] = encoded([row['request'] for row in url_cases()])
        inputs['urls/'+label+'/expected.json'] = encoded(url_expected(names, namespace))
    return inputs


def source_provenance(module_metadata):
    """Bind actual downloaded decision/handler sources, not merely their version string."""
    metadata = read_json(module_metadata)
    roots = {'kubernetes': Path(metadata['Dir']), 'apiserver': Path(metadata['Dir']).parent/'apiserver@v0.34.0'}
    pins = read_json(HERE/'source-pins.json')
    require(isinstance(pins, dict) and set(pins) == {'kubernetes', 'apiserver'}, 'Wrong source module inventory')
    result = {}
    for module, entries in pins.items():
        require(isinstance(entries, dict) and set(entries) == set(SOURCE_FILES[module]), 'Missing/extra pinned module sources')
        for relative, sha in entries.items():
            require(isinstance(relative, str) and not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Unsafe source path')
            path = roots[module]/relative
            require(isinstance(sha, str) and digest(path) == sha, 'Pinned upstream source differs: '+str(path))
            result[str(path)] = sha
    return result


def planned_counts(native_only=False):
    rows, cases, urls = matrix_requests(), contract_cases(), url_cases()
    native = sum(len([r for r in rows if c['contract']['schema_version'] == 7 or r['subresource'] == '']) *
        (2 if c['baseline'] is not None else 1) for c in cases)
    return dict(matrix_comparisons=len(rows)*len(matrix_cases()), url_comparisons=len(urls)*len(url_policies()),
        contract_native_checks=native, rejected_requests=0 if native_only else len(rejection_requests())+sum(not r['supported'] for r in urls),
        legacy_rejected_requests=0 if native_only else sum(bool(r['subresource']) for r in rows),
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
            if case['baseline'] is not None:
                entry['comparison'] = case['comparison']
        expected_cases['contracts/'+case['id']] = entry
    require(encoded(result.get('cases')) == encoded(expected_cases), 'Missing/altered completed case inventory')
    require(result.get('inputs_unchanged') is True and result.get('binaries_unchanged') is True, 'Unverified provenance stability')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ['model', 'soundcheck']:
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    result = dict(complete=False, profile=PROFILE, native_only=args.native_only, cases={}, failures=[], input_sha256={},
        **{key: 0 for key in planned_counts()}, limits=[
            'Frozen synthetic initial RBAC checks against Kubernetes1.34.0, not API execution or a deployed-cluster benchmark.',
            'Named subresource create differs from empty-name top-level create. Names identify the parent in the URL.',
            'Exec admission, connection effects, newer WebSocket create checks, TokenRequest contents/issuance and admission are outside this model.',
            'Finite native/concrete/SMT agreement and witness replay are not a universal proof of implementation correctness.',
            'Schemas1–6 retain their original domains; schema7 explicitly opts into19 subresource operations.'])
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
        result['source_sha256'] = {str(path): digest(path) for path in [Path(__file__), HERE/'inputs.json', HERE/'contract.json', HERE/'source-pins.json', args.module_metadata]+
            [source_dir/name for name in ['run.py', 'run_scopes.py', 'run_write_access.py', 'run_read_access.py', 'run_resources.py', 'run_collection_writes.py', 'oracle/go.mod', 'oracle/go.sum', 'oracle/module-pins.json']]+
            sorted((source_dir/'oracle').glob('*.go'))}
        binaries = [args.reference]
        z3 = None
        if not args.native_only:
            require(args.model is not None and args.soundcheck is not None, 'Production comparison needs model and soundcheck')
            z3 = shutil.which(args.z3)
            require(z3 is not None, 'Z3 is required')
            binaries += [args.model, args.soundcheck, Path(z3)]
        result['binary_sha256'] = {str(path): digest(path) for path in binaries}
        # Write a full input/source/tool receipt before any executable is run.
        save(args.output.parent/'before-execution.json', result)
        save(args.output, result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-subresource-z3-') as temporary:
            environment = dict(os.environ)
            if z3 is not None:
                Path(temporary, 'z3').symlink_to(Path(z3).resolve())
                environment['PATH'] = temporary+os.pathsep+environment.get('PATH', '')
            def native(manifest, rows, folder, label):
                path = folder/(label+'-requests.json')
                save(path, rows)
                return decisions(execute([args.reference, manifest, path], folder/(label+'-reference.json'), environment), rows, 'reference')
            def agree(manifest, spec_path, rows, folder, label, expected=None):
                spec = read_json(spec_path)
                for row in rows:
                    validate_request(row, version=spec['schema_version'])
                upstream = native(manifest, rows, folder, label)
                if expected is not None:
                    require(upstream == expected, 'Literal expected grants differ: '+label)
                if not args.native_only:
                    model = execute([args.model, manifest, spec_path, folder/(label+'-requests.json')], folder/(label+'-model.json'), environment)
                    concrete = decisions(model, rows, 'model')
                    symbolic = smt_decisions(model, rows, folder, label, z3, environment)
                    require(upstream == concrete == symbolic, 'Native/concrete/SMT mismatch: '+label)
                return upstream
            rows = matrix_requests()
            for case in matrix_cases():
                folder = artifacts/'matrix'/case['id']
                agree(folder/'snapshot.json', artifacts/'contract.json', rows, folder, 'matrix', case['expected'])
                result['matrix_comparisons'] += len(rows)
                result['cases']['matrix/'+case['id']] = dict(matrix_comparisons=len(rows))
                print(case['id']+': frozen expectations agree', flush=True)
                save(args.output, result)
            for case in contract_cases():
                folder = artifacts/'contracts'/case['id']
                manifest, spec_path, spec = folder/'snapshot.json', folder/'contract.json', case['contract']
                finite = [r for r in rows if spec['schema_version'] == 7 or r['subresource'] == '']
                observed = native(manifest, finite, folder, 'finite')
                failed = []
                for selected in spec['clauses']:
                    points = [r for r in finite if scope_matches(selected, r)]
                    require(points, 'Finite corpus does not inhabit clause '+selected['name'])
                    wanted = 'Allow' if selected['kind'] == 'must_allow' else 'NoOpinion'
                    if any(observed[r['id']] != wanted for r in points):
                        failed.append(selected['name'])
                require(bool(failed) == (case['expected'] == 'violated'), 'Native contract differs: '+case['id'])
                if failed:
                    require(failed[0] == case['failed'], 'Unexpected first native failing clause')
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
                    if report['result'] == 'violated':
                        replay(report)
                    if case['baseline'] is not None:
                        compared = audit_report(execute([args.soundcheck, 'rbac', 'compare', folder/'baseline.json', manifest, '--contract', spec_path, '--format', 'json'], folder/'compare.json', environment), spec, case['comparison'], True)
                        entry['comparison'] = compared['result']
                        if compared['result'] == 'violated':
                            replay(compared, True)
                result['cases']['contracts/'+case['id']] = entry
                print(case['id']+': native contract/preservation checked', flush=True)
                save(args.output, result)
            excluded = []
            for label, names, namespace in url_policies():
                folder, fixed = artifacts/'urls'/label, url_expected(names, namespace)
                extracted = audit_urls(execute([args.reference, '--request-urls', folder/'snapshot.json', folder/'requests.json'], folder/'reference.json', environment), fixed)
                supported = []
                for case in fixed:
                    attrs = dict(extracted[case['request']['id']])
                    del attrs['apiVersion'], attrs['path']
                    row = dict(attrs, id=case['request']['id'])
                    if case['supported']:
                        supported.append(row)
                    elif label == 'unrestricted':
                        excluded.append(row)
                agree(folder/'snapshot.json', artifacts/'contract.json', supported, folder, 'extracted', {c['request']['id']: c['decision'] for c in fixed if c['supported']})
                result['url_comparisons'] += len(fixed)
                print('urls-'+label+': native attributes and decisions agree', flush=True)
                save(args.output, result)
            if not args.native_only:
                def reject(row, spec_path, label):
                    path = artifacts/'rejections'/(label+'.json')
                    save(path, [row])
                    model = execute([args.model, artifacts/'urls'/'unrestricted'/'snapshot.json', spec_path, path], artifacts/'rejections'/(label+'-model.json'), environment)
                    require(decisions(model, [row], 'model', allow_unsupported=True) is None, 'Outside-domain request received a decision: '+label)
                for row in rejection_requests()+excluded:
                    reject(row, artifacts/'contract.json', row['id'])
                    result['rejected_requests'] += 1
                for row in rows:
                    if row['subresource']:
                        reject(row, artifacts/'legacy-contract.json', 'v6-'+row['id'])
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
