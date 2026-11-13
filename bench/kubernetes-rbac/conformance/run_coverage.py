#!/usr/bin/env python3
"""Frozen schema-9 static RBAC coverage against Kubernetes 1.34.0.

Initial decisions use native HTTP RequestInfo and GetAuthorizerAttributes.
Conditional PUT uses native UpdateResource, strategies and generic storage.
The catalogue is a reviewed authorization domain, not endpoint discovery.
"""
import argparse
import copy
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

from run import (DNS_LABEL, DNS_SUBDOMAIN, EXIT_CODES, decisions, digest, execute,
                 module_provenance, read_json, require, save, smt_decisions,
                 strict_json, strings, valid_dns)
from run_resources import IDENTITIES, rule, grant, snapshot, encoded, byte_hash, audit_pins
import run_apply as apply
import run_resources as resources
import run_collection_writes as collections
import run_subresources as subresources

HERE = Path(__file__).resolve().parent.parent/'coverage'
PROFILE = 'kubernetes-rbac-v1.34-static-coverage-v1'
HTTP_OPERATIONS = ['get', 'head', 'post', 'put', 'patch', 'delete', 'options']
PUT_OPERATIONS = ['update-existing', 'update-missing']
NEW_BASES = [('', 'serviceaccounts', True), ('', 'events', True), ('', 'namespaces', False),
    ('', 'persistentvolumeclaims', True), ('', 'persistentvolumes', False),
    ('events.k8s.io', 'events', True), ('apps', 'replicasets', True), ('apps', 'statefulsets', True),
    ('apps', 'daemonsets', True), ('batch', 'jobs', True), ('batch', 'cronjobs', True),
    ('coordination.k8s.io', 'leases', True), ('networking.k8s.io', 'ingresses', True),
    ('networking.k8s.io', 'ingressclasses', False), ('storage.k8s.io', 'storageclasses', False)]
CUSTOM = [dict(api_group='widgets.example.test', resource='widgets', scope='Namespaced', subresources=['status', 'scale']),
          dict(api_group='widgets.example.test', resource='clusterwidgets', scope='Cluster', subresources=['status', 'scale'])]
CATALOGUE = copy.deepcopy(apply.CATALOGUE)
CATALOGUE += [(g, r, '', ns, collections.VERBS) for g, r, ns in NEW_BASES]
CATALOGUE = [(g, r, s, ns, list(ops)+(PUT_OPERATIONS if g == s == '' and r in ['services', 'endpoints'] else []))
             for g, r, s, ns, ops in CATALOGUE]
for item in CUSTOM:
    CATALOGUE.append((item['api_group'], item['resource'], '', item['scope'] == 'Namespaced', collections.VERBS))
    for subresource in item['subresources']:
        CATALOGUE.append((item['api_group'], item['resource'], subresource, item['scope'] == 'Namespaced', ['get', 'update', 'patch']))
KINDS = {r+('/'+s if s else '')+('.'+g if g else ''): (g, r, s, ns) for g, r, s, ns, _ in CATALOGUE}
SOURCE_FILES = copy.deepcopy(apply.SOURCE_FILES)
SOURCE_FILES['kubernetes'] += ['pkg/registry/core/namespace/storage/storage.go',
    'pkg/registry/core/namespace/strategy.go', 'test/integration/client/client_test.go']
SOURCE_FILES['kubernetes'] += ['pkg/registry/'+p+'/strategy.go' for p in [
    'core/serviceaccount', 'core/event', 'core/persistentvolumeclaim', 'core/persistentvolume',
    'apps/replicaset', 'apps/statefulset', 'apps/daemonset', 'batch/job', 'batch/cronjob',
    'coordination/lease', 'networking/ingress', 'networking/ingressclass', 'storage/storageclass']]
SOURCE_FILES['kubernetes'] += ['pkg/registry/events/rest/storage_events.go']
LINKAGE = dict(apply.LINKAGE, **{
    'update-handler': ('apiserver', 'pkg/endpoints/handlers/update.go', 51, 'pkg/endpoints/handlers.UpdateResource'),
    'authorizer-attributes': ('apiserver', 'pkg/endpoints/filters/authorization.go', 101, 'pkg/endpoints/filters.GetAuthorizerAttributes'),
    'request-classifier': ('apiserver', 'pkg/endpoints/request/requestinfo.go', 129, 'pkg/endpoints/request.(*RequestInfoFactory).NewRequestInfo'),
    'rbac-authorizer': ('kubernetes', 'plugin/pkg/auth/authorizer/rbac/rbac.go', 75, 'plugin/pkg/auth/authorizer/rbac.(*RBACAuthorizer).Authorize')})


def scope(resource='configmaps', group='', subresource='', operation='get', namespace='team-a', names=None, subject='app'):
    return dict(request_kind='resource', subject=subject, operation=operation, api_group=group,
                resource=resource, subresource=subresource, namespace=namespace, names=names)


def url_scope(path='/healthz', prefix=False, operation='get', subject='app'):
    return dict(request_kind='non_resource', subject=subject, operation=operation,
                paths={'prefix' if prefix else 'exact': path})


def clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **scope(**kwargs))


def url_clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **url_scope(**kwargs))


def contract(clauses=None, changes=(), custom=None):
    if clauses is None:
        clauses = [clause('required-config', 'must_allow', names=['settings']),
                   clause('forbidden-secrets', 'must_not_grant', resource='secrets')]
    result = resources.contract(clauses, changes, version=9)
    result['custom_resources'] = copy.deepcopy(CUSTOM if custom is None else custom)
    return result


def request(group='', resource='configmaps', subresource='', operation='get', namespace='team-a', name='settings', user='app', id_='request'):
    return dict(id=id_, username=user, groups=list(IDENTITIES[user]), operation=operation, apiGroup=group,
                resource=resource, namespace=namespace, name=name, resourceRequest=True, subresource=subresource)


def url_request(path='/healthz', operation='get', user='app', id_='request'):
    return dict(id=id_, username=user, groups=list(IDENTITIES[user]), operation=operation, resourceRequest=False, path=path)


def canonical_url(path):
    if not isinstance(path, str) or not path.startswith('/') or not re.fullmatch(r'/[A-Za-z0-9._~/-]*', path):
        return False
    parts = path[1:].split('/')
    if parts[-1] == '': parts.pop()
    return all(part and part not in ['.', '..'] for part in parts)


def nonresource_path(path):
    if not canonical_url(path): return False
    parts = path.strip('/').split('/') if path != '/' else []
    return not (len(parts) >= 3 and parts[0] == 'api' or len(parts) >= 4 and parts[0] == 'apis')


def validate_request(row, identities=IDENTITIES, custom=CUSTOM):
    require(isinstance(row, dict) and isinstance(row.get('id'), str) and row['id'], 'Missing request id')
    require(row.get('username') in identities and strings(row.get('groups'), nonempty=True)
        and len(set(row['groups'])) == len(row['groups']) and sorted(row['groups']) == sorted(identities[row['username']]), 'Wrong frozen identity')
    require(type(row.get('resourceRequest')) is bool, 'Resource discriminator must be boolean')
    if not row['resourceRequest']:
        require(set(row) == {'id', 'username', 'groups', 'operation', 'resourceRequest', 'path'}, 'Wrong nonresource request shape')
        require(row['operation'] in HTTP_OPERATIONS and nonresource_path(row['path']), 'Outside nonresource request domain')
        return
    require(set(row) == {'id', 'username', 'groups', 'operation', 'resourceRequest', 'apiGroup', 'resource', 'namespace', 'name', 'subresource'}, 'Wrong resource request shape')
    catalogue = [x for x in CATALOGUE if not x[0].endswith('.example.test')]
    for entry in custom:
        catalogue.append((entry['api_group'], entry['resource'], '', entry['scope'] == 'Namespaced', collections.VERBS))
        catalogue.extend((entry['api_group'], entry['resource'], s, entry['scope'] == 'Namespaced', ['get', 'update', 'patch']) for s in entry['subresources'])
    matches = [x for x in catalogue if x[:3] == (row['apiGroup'], row['resource'], row['subresource'])]
    require(len(matches) == 1 and row['operation'] in matches[0][4], 'Outside reviewed resource/operation catalogue')
    _, resource, subresource, namespaced, _ = matches[0]
    op, ns, name = row['operation'], row['namespace'], row['name']
    read = subresource == '' and op in ['list', 'watch']
    collection = subresource == '' and op in ['create', 'deletecollection']
    if resource == 'namespaces' and row['apiGroup'] == '':
        if read or collection:
            require(ns == '', 'Namespace collection authorization namespace must be empty')
        else:
            require(ns == name and valid_dns(name, 63, DNS_LABEL), 'Named Namespace authorization namespace must equal its name')
    elif namespaced:
        require((read and ns == '') or valid_dns(ns, 63, DNS_LABEL), 'Invalid named namespace')
    else:
        require(ns == '', 'Cluster request namespace must be empty')
    if collection:
        require(name == '', 'Collection write authorization name must be empty')
    else:
        require((read and name == '') or valid_dns(name, 253, DNS_SUBDOMAIN), 'Invalid authorization name')


URL_PATHS = ['/', '/healthz', '/healthz/', '/healthz/ping', '/healthzish', '/readyz', '/readyz/ping', '/metrics',
    '/version', '/api', '/api/v1', '/api/v1/', '/apis', '/apis/apps', '/apis/apps/v1', '/openapi/v3',
    '/openapi/v3/apis/apps/v1', '/custom', '/custom/item', '/unseen']


def matrix_requests():
    rows = []
    for group, resource, subresource, namespaced, operations in CATALOGUE:
        for operation in operations:
            read = subresource == '' and operation in ['list', 'watch']
            collection = subresource == '' and operation in ['create', 'deletecollection']
            namespaces = ['team-a', 'team-b', 'fresh-ns']+([''] if read else []) if namespaced else ['']
            names = [''] if collection else ['settings', 'other', 'fresh-name']+([''] if read else [])
            if group == '' and resource == 'namespaces' and read: names.append('team-a')
            pairs = [(ns, name) for ns in namespaces for name in names]
            if resource == 'namespaces' and group == '' and not (read or collection):
                pairs = [(ns, ns) for ns in ['team-a', 'team-b', 'fresh-ns']]
            for namespace, name in pairs:
                for user in IDENTITIES:
                    rows.append(request(group, resource, subresource, operation, namespace, name, user, str(len(rows))))
    for path in URL_PATHS:
        for op in HTTP_OPERATIONS:
            for user in IDENTITIES:
                rows.append(url_request(path, op, user, str(len(rows))))
    return rows


def prerequisites(row):
    return {'apply-existing': ['patch'], 'apply-missing': ['patch', 'create'],
            'update-existing': ['update'], 'update-missing': ['update', 'create']}.get(row['operation'], [row['operation']])


def matrix_cases():
    rows, cases = matrix_requests(), []
    def add(id_, items, permitted):
        expected = {}
        for r in rows:
            stages = []
            for op in prerequisites(r):
                allowed = permitted(dict(r, operation=op))
                stages.append('Allow' if allowed else 'NoOpinion')
                if not allowed: break
            expected[r['id']] = dict(decision='Allow' if all(s == 'Allow' for s in stages) else 'NoOpinion', stages=stages)
        cases.append(dict(id=id_, snapshot=snapshot(items), expected=expected))
    app = lambda r: r['username'] == 'app'
    resource = lambda r: r['resourceRequest']
    add('empty', [], lambda r: False)
    add('all-resource-grants', grant('resources', [rule(('*',), ('*',), ['*'])]), lambda r: app(r) and resource(r))
    add('all-url-grants', grant('urls', [dict(verbs=['*'], nonResourceURLs=['*'])]), lambda r: app(r) and not resource(r))
    add('both-request-kinds', grant('both', [rule(('*',), ('*',), ['*']), dict(verbs=['*'], nonResourceURLs=['*'])]), app)
    add('local-resource-grants', grant('local', [rule(('*',), ('*',), ['*'])], 'team-a', local_role=True),
        lambda r: app(r) and resource(r) and r['namespace'] == 'team-a')
    add('local-url-nongrants', grant('local-url', [dict(verbs=['*'], nonResourceURLs=['*'])], 'team-a'), lambda r: False)
    for verb in ['get', 'update', 'create', 'patch']:
        add('resource-'+verb, grant(verb, [rule(('*',), ('*',), [verb])]), lambda r, v=verb: app(r) and resource(r) and r['operation'] == v)
    add('separate-update-create', grant('update', [rule(('*',), ('*',), ['update'])])+grant('create', [rule(('*',), ('*',), ['create'])]),
        lambda r: app(r) and resource(r) and r['operation'] in ['update', 'create'])
    add('named-update-create', grant('named', [rule(('*',), ('*',), ['update', 'create'], ['settings'])]),
        lambda r: app(r) and resource(r) and r['operation'] in ['update', 'create'] and r['name'] == 'settings')
    add('empty-create-name', grant('updater', [rule(('*',), ('*',), ['update'])])+grant('empty', [rule(('*',), ('*',), ['create'], [''])]),
        lambda r: app(r) and resource(r) and (r['operation'] == 'update' or r['operation'] == 'create' and r['name'] == ''))
    add('custom-only', grant('custom', [rule(('widgets.example.test',), ('widgets',), ['*'])], 'team-a'),
        lambda r: app(r) and resource(r) and r['apiGroup'] == 'widgets.example.test' and r['resource'] == 'widgets' and r['subresource'] == '' and r['namespace'] == 'team-a')
    add('custom-scale', grant('scale', [rule(('widgets.example.test',), ('*/scale',), ['get', 'update'])]),
        lambda r: app(r) and resource(r) and r['apiGroup'] == 'widgets.example.test' and r['subresource'] == 'scale' and r['operation'] in ['get', 'update'])
    add('namespace-names', grant('namespaces', [rule(('',), ('namespaces',), ['*'], ['team-a'])], 'team-a'),
        lambda r: app(r) and resource(r) and r['apiGroup'] == '' and r['resource'] == 'namespaces' and r['name'] == r['namespace'] == 'team-a')
    for id_, urls, verb, predicate in [
        ('exact-url', ['/healthz'], 'get', lambda p: p == '/healthz'),
        ('prefix-url', ['/healthz*'], 'get', lambda p: p.startswith('/healthz')),
        ('slash-prefix-url', ['/healthz/*'], 'get', lambda p: p.startswith('/healthz/')),
        ('trailing-stars-url', ['/healthz***'], 'get', lambda p: p.startswith('/healthz')),
        ('discovery-prefix-url', ['/api*'], '*', lambda p: p.startswith('/api')),
        ('head-only-url', ['/readyz'], 'head', lambda p: p == '/readyz'),
        ('literal-middle-star-url', ['/health*z'], 'get', lambda p: p == '/health*z')]:
        add(id_, grant(id_, [dict(verbs=[verb], nonResourceURLs=urls)]),
            lambda r, v=verb, pred=predicate: app(r) and not resource(r) and (v == '*' or r['operation'] == v) and pred(r['path']))
    add('independent-ops', grant('ops-resources', [rule(('*',), ('*',), ['get'])], subject='ops')+
        grant('ops-urls', [dict(verbs=['get'], nonResourceURLs=['/healthz*'])], subject='ops'),
        lambda r: r['username'] == 'ops' and r['operation'] == 'get' and (resource(r) or r['path'].startswith('/healthz')))
    return cases


def as_url(row):
    if not row['resourceRequest']:
        return dict(id=row['id'], username=row['username'], groups=row['groups'], method=row['operation'].upper(), url=row['path'])
    op, name, ns, group, resource, sub = [row[k] for k in ['operation', 'name', 'namespace', 'apiGroup', 'resource', 'subresource']]
    require(op not in apply.NEW_OPERATIONS+PUT_OPERATIONS, 'Compound operation needs native handler')
    path = '/apis/'+group+'/v1' if group else '/api/v1'
    if ns and resource != 'namespaces': path += '/namespaces/'+ns
    path += '/'+resource
    read = sub == '' and op in ['list', 'watch']
    if name and not read: path += '/'+name
    if sub: path += '/'+sub
    query = []
    if op == 'watch': query.append('watch=true')
    if read and name: query.append('fieldSelector=metadata.name%3D'+quote(name, safe=''))
    method = {'get': 'GET', 'list': 'GET', 'watch': 'GET', 'update': 'PUT', 'patch': 'PATCH', 'delete': 'DELETE', 'create': 'POST', 'deletecollection': 'DELETE'}[op]
    return dict(id=row['id'], username=row['username'], groups=row['groups'], method=method, url=path+('?'+'&'.join(query) if query else ''))


def expected_attributes(row, verb=None, compound=False):
    if not row['resourceRequest']:
        return dict(username=row['username'], groups=row['groups'], verb=row['operation'], apiGroup='', apiVersion='', resource='',
            namespace='', name='', subresource='', resourceRequest=False, path=row['path'])
    if compound:
        value = apply.expected_attributes(row, verb, True)
    else:
        value = dict(username=row['username'], groups=row['groups'], verb=row['operation'], apiGroup=row['apiGroup'], apiVersion='v1',
            resource=row['resource'], namespace=row['namespace'], name=row['name'], subresource=row['subresource'], resourceRequest=True,
            path=urlsplit(as_url(row)['url']).path)
    return value


def scope_matches(selected, row):
    if selected['subject'] != row['username'] or selected['operation'] != row['operation']: return False
    if selected['request_kind'] == 'non_resource':
        if row['resourceRequest']: return False
        paths = selected['paths']
        return row['path'] == paths['exact'] if 'exact' in paths else row['path'].startswith(paths['prefix'])
    if not row['resourceRequest']: return False
    reduced = {k: v for k, v in selected.items() if k != 'request_kind'}
    return apply.scope_matches(reduced, row)


def contract_cases():
    common = grant('required-config', [rule(('',), ('configmaps',), ['get'], ['settings'])], 'team-a')
    cases = []
    def add(id_, spec, items, expected='proved', failed=None, baseline=None, comparison=None, preservation=None):
        cases.append(dict(id=id_, contract=spec, snapshot=snapshot(items), expected=expected, failed=failed,
            baseline=snapshot(baseline) if baseline is not None else None, comparison=comparison, preservation=preservation))
    for group, resource, namespaced in NEW_BASES:
        namespace = 'team-a' if namespaced or resource == 'namespaces' else None
        name = 'team-a' if resource == 'namespaces' else 'settings'
        spec = contract([clause('required-new-resource', 'must_allow', group=group, resource=resource, namespace=namespace, names=[name]),
                         clause('forbidden-secrets', 'must_not_grant', resource='secrets')])
        add('builtin-'+resource+('-'+group if group else ''), spec, grant('new', [rule((group,), (resource,), ['get'])]))
    local_namespace = grant('namespace-local', [rule(('',), ('namespaces',), ['get', 'list', 'watch'], ['team-a'])], 'team-a', local_role=True)
    spec = contract([clause('required-named-namespace', 'must_allow', resource='namespaces', namespace='team-a', names=['team-a']),
        clause('forbidden-selected-namespace-list', 'must_not_grant', resource='namespaces', operation='list', namespace=None, names=['team-a'])])
    add('namespace-named-versus-selected-list', spec, local_namespace)
    add('namespace-cluster-binding-exposes-list', spec, grant('namespace-global', [rule(('',), ('namespaces',), ['get', 'list', 'watch'], ['team-a'])]), 'violated', 'forbidden-selected-namespace-list')
    add('namespace-local-does-not-allow-other', contract([clause('required-named-namespace', 'must_allow', resource='namespaces', namespace='team-a', names=['team-a']),
        clause('forbidden-other-namespace', 'must_not_grant', resource='namespaces', namespace={'exclude': ['team-a']})]), local_namespace)
    for item in CUSTOM:
        ns = 'team-a' if item['scope'] == 'Namespaced' else None
        for sub in ['', 'status', 'scale']:
            qualified = item['resource']+('/'+sub if sub else '')
            spec = contract([clause('required-custom', 'must_allow', resource=item['resource'], group=item['api_group'], subresource=sub, namespace=ns, names=['settings']),
                clause('forbidden-secrets', 'must_not_grant', resource='secrets')])
            add('custom-'+item['resource']+'-'+(sub or 'base'), spec, grant('custom', [rule((item['api_group'],), (qualified,), ['get'])]))
    for resource in ['services', 'endpoints']:
        update = grant('updater', [rule(('',), (resource,), ['update'], ['settings'])], 'team-a')
        create = grant('creator', [rule(('',), (resource,), ['create'], ['settings'])], 'team-a')
        fixed = contract([clause('required-existing', 'must_allow', resource=resource, operation='update-existing', names=['settings']),
            clause('forbidden-missing', 'must_not_grant', resource=resource, operation='update-missing', names=['settings'])])
        add(resource+'-existing-only', fixed, update)
        add(resource+'-unsafe-create', fixed, update+create, 'violated', 'forbidden-missing')
        allow_missing = contract([clause('required-missing', 'must_allow', resource=resource, operation='update-missing', names=['settings']),
            clause('forbidden-ordinary-create', 'must_not_grant', resource=resource, operation='create', names={'empty': True})])
        add(resource+'-named-create-is-not-post', allow_missing, update+create)
        add(resource+'-partial-repair-loses-required', allow_missing, update, 'violated', 'required-missing')
    for id_, urls, target, prefix in [
        ('url-exact', ['/healthz'], '/healthz', False),
        ('url-prefix', ['/healthz*'], '/healthz', True),
        ('url-trailing-stars', ['/healthz***'], '/healthz', True),
        ('url-discovery-prefix', ['/api*'], '/api', True)]:
        spec = contract([url_clause('required-url', 'must_allow', path=target, prefix=prefix),
            url_clause('forbidden-metrics', 'must_not_grant', path='/metrics')])
        add(id_, spec, grant('url', [dict(verbs=['get'], nonResourceURLs=urls)]))
    add('url-exact-does-not-cover-prefix', contract([url_clause('required-url', 'must_allow', path='/healthz', prefix=True),
        url_clause('forbidden-metrics', 'must_not_grant', path='/metrics')]), grant('exact', [dict(verbs=['get'], nonResourceURLs=['/healthz'])]), 'violated', 'required-url')
    add('resource-wildcard-does-not-grant-url', contract([clause('required-config', 'must_allow', names=['settings']),
        url_clause('forbidden-url', 'must_not_grant', path='/', prefix=True)]), grant('resources', [rule(('*',), ('*',), ['*'])]))
    add('url-wildcard-does-not-grant-resource', contract([url_clause('required-url', 'must_allow', path='/healthz'),
        clause('forbidden-secrets', 'must_not_grant', resource='secrets')]), grant('urls', [dict(verbs=['*'], nonResourceURLs=['*'])]))
    urls = grant('metrics', [dict(verbs=['get'], nonResourceURLs=['/metrics'])], subject='ops')
    add('preserve-unmentioned-url', contract(), common+urls[:1], baseline=common+urls, comparison='violated',
        preservation=dict(kind='non_resource', operation='get', user='ops'))
    custom = grant('custom-status', [rule(('widgets.example.test',), ('widgets/status',), ['update'])], 'team-b', subject='ops')
    add('preserve-unmentioned-custom-status', contract(), common+custom[:1], baseline=common+custom, comparison='violated',
        preservation=dict(kind='widgets/status.widgets.example.test', operation='update', user='ops'))
    update = grant('service-update', [rule(('',), ('services',), ['update'], ['settings'])], 'team-b', subject='ops')
    restricted = contract(changes=[scope(resource='services', operation='update', namespace='team-b', names=['settings'], subject='ops')])
    add('ordinary-update-scope-does-not-cover-existing', restricted, common+update[:1], baseline=common+update, comparison='violated',
        preservation=dict(kind='services', operation='update-existing', user='ops'))
    create = grant('service-create', [rule(('',), ('services',), ['create'], ['settings'])], 'team-b', subject='ops')
    add('preserve-unmentioned-put-missing', contract(), common+update+create[:1], baseline=common+update+create, comparison='violated',
        preservation=dict(kind='services', operation='update-missing', user='ops'))
    add('approved-put-change', contract(changes=[scope(resource='services', operation='update-missing', namespace='team-b', names=['settings'], subject='ops')]),
        common+update+create[:1], baseline=common+update+create, comparison='proved')
    health = grant('health', [dict(verbs=['get'], nonResourceURLs=['/healthz*'])], subject='ops')
    add('approved-url-prefix-change', contract(changes=[url_scope(path='/healthz', prefix=True, subject='ops')]),
        common+health[:1], baseline=common+health, comparison='proved')
    add('resource-scope-cannot-approve-url-change', contract(changes=[scope(subject='ops')]),
        common+urls[:1], baseline=common+urls, comparison='violated', preservation=dict(kind='non_resource', operation='get', user='ops'))
    add('url-scope-cannot-approve-resource-change', contract(changes=[url_scope(path='/', prefix=True, subject='ops')]),
        common+custom[:1], baseline=common+custom, comparison='violated', preservation=dict(kind='widgets/status.widgets.example.test', operation='update', user='ops'))
    return cases


def normalized_contract(spec):
    value = copy.deepcopy(spec)
    for identity in value['context']['identities']: identity['groups'].sort()
    value['context']['identities'].sort(key=lambda i: i['username'])
    for selected in value['clauses']+value['change_scope']:
        for field in ['namespace', 'names']:
            selector = selected.get(field)
            if isinstance(selector, list): selector.sort()
            elif isinstance(selector, dict):
                for entry in selector.values():
                    if isinstance(entry, list): entry.sort()
    for entry in value['custom_resources']: entry['subresources'].sort()
    value['custom_resources'].sort(key=lambda e: (e['api_group'], e['resource']))
    value['change_scope'] = [strict_json(k.decode()) for k in sorted({encoded(s) for s in value['change_scope']})]
    return value


def audit_native_urls(execution, rows, expected=None):
    require(type(execution.get('returncode')) is int and execution['returncode'] == 0, 'Native URL reference failed')
    value = execution.get('data')
    require(isinstance(value, dict) and set(value) == {'schema_version', 'kind', 'valid', 'validation_errors', 'decisions'}, 'Wrong URL reference shape')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['kind'] == 'rbac_coverage_url_authorization'
        and value['valid'] is True and value['validation_errors'] == [], 'Invalid native URL result')
    require(isinstance(value['decisions'], list) and len(value['decisions']) == len(rows), 'Missing URL decisions')
    by_id = {r['id']: r for r in rows}; require(len(by_id) == len(rows), 'Duplicate requested URL id')
    observed = {}
    for entry in value['decisions']:
        require(isinstance(entry, dict) and set(entry) == {'id', 'decision', 'reason', 'error', 'attributes', 'field_selector_error', 'label_selector_error'}, 'Wrong URL decision shape')
        require(entry['id'] in by_id and entry['id'] not in observed, 'Missing/duplicate URL id')
        require(entry['decision'] in ['Allow', 'NoOpinion'] and entry['error'] == '' and isinstance(entry['reason'], str), 'Native URL error is not NoOpinion')
        require(entry['field_selector_error'] is False and entry['label_selector_error'] is False, 'Unexpected selector parsing error')
        require(encoded(entry['attributes']) == encoded(expected_attributes(by_id[entry['id']])), 'Native full request attributes differ')
        if expected is not None:
            require(expected[entry['id']] == dict(decision=entry['decision'], stages=[entry['decision']]), 'Frozen URL decision differs')
        observed[entry['id']] = entry['decision']
    require(set(observed) == set(by_id), 'Incomplete URL inventory')
    return observed


def audit_native_put(execution, rows, expected=None):
    # Reuse the already independently tested strict SSA evidence consumer, after
    # translating only its expected operation names and initial verb. Native
    # output remains unchanged on disk and its original PUT shape is checked.
    require(type(execution.get('returncode')) is int and execution['returncode'] == 0, 'Native PUT execution failed')
    value = execution.get('data')
    require(isinstance(value, dict) and value.get('kind') == 'rbac_put_authorization', 'Wrong PUT reference kind')
    changed = copy.deepcopy(execution)
    changed['data']['kind'] = 'rbac_apply_authorization'
    for entry in changed['data'].get('decisions', []):
        stages = entry.get('stages')
        require(isinstance(stages, list) and stages and isinstance(stages[0], dict), 'Missing PUT stages')
        attrs = stages[0].get('attributes')
        require(isinstance(attrs, dict) and attrs.get('verb') == 'update', 'PUT initial verb must be update')
        attrs['verb'] = 'patch'
    adjusted_rows = [dict(r, operation='apply-existing' if r['operation'] == 'update-existing' else 'apply-missing') for r in rows]
    require(all(r['operation'] in PUT_OPERATIONS and r['apiGroup'] == '' and r['resource'] in ['services', 'endpoints'] and r['subresource'] == '' for r in rows), 'Outside PUT reference catalogue')
    return apply.audit_native(changed, adjusted_rows, expected)


def audit_linkage(execution):
    require(type(execution.get('returncode')) is int and execution['returncode'] == 0, 'Native linkage command failed')
    value = execution.get('data')
    require(isinstance(value, dict) and set(value) == {'schema_version', 'kind', 'go_version', 'modules', 'functions', 'resource_scopes'}, 'Wrong linkage shape')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['kind'] == 'rbac_coverage_native_linkage', 'Wrong linkage schema')
    require(isinstance(value['go_version'], str) and value['go_version'].startswith('go1.'), 'Missing Go version')
    versions = {'kubernetes': 'v1.34.0', 'apiserver': 'v0.34.0', 'api': 'v0.34.0', 'apimachinery': 'v0.34.0'}
    require(isinstance(value['modules'], dict), 'Missing compiled modules')
    for module, version in versions.items(): require(value['modules'].get('k8s.io/'+module) == version, 'Wrong compiled module: '+module)
    require(encoded(value['resource_scopes']) == encoded({r+('.'+g if g else ''): ns for g, r, ns in NEW_BASES}), 'Native resource scope disagrees with frozen catalogue')
    require(isinstance(value['functions'], dict) and set(value['functions']) == set(LINKAGE), 'Wrong native function inventory')
    for label, (module, source, line, function) in LINKAGE.items():
        observed = value['functions'][label]
        require(isinstance(observed, dict) and set(observed) == {'function', 'file', 'line'}, 'Wrong linked function shape')
        require(observed['function'] == 'k8s.io/'+module+'/'+function and type(observed['line']) is int and observed['line'] in [line, line+1], 'Wrong native function: '+label)
        require(isinstance(observed['file'], str) and observed['file'].endswith('k8s.io/'+module+'@'+versions[module]+'/'+source), 'Wrong native source: '+label)
    return value


def audit_report(execution, spec, expected, comparison=False):
    value = execution.get('data')
    require(isinstance(value, dict) and value.get('result') == expected and type(execution.get('returncode')) is int and execution['returncode'] == EXIT_CODES[expected], 'Wrong verdict/exit')
    require(type(value.get('schema_version')) is int and value['schema_version'] == 10, 'Wrong report schema')
    require(value.get('property') == ('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'), 'Wrong property')
    require(value.get('assurance') == dict(profile=PROFILE, status='within_profile', findings=[]), 'Wrong assurance')
    frozen = value.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and frozen['schema_version'] == 9
        and frozen.get('kind') == spec['kind'] and isinstance(frozen.get('canonical'), str), 'Missing frozen identity')
    require(encoded(normalized_contract(strict_json(frozen['canonical']))) == encoded(normalized_contract(spec)), 'Frozen contract changed')
    if expected != 'violated': require(value.get('counterexample') is None, 'Unexpected witness')
    if expected == 'proved': require(value.get('clause') is None, 'Unexpected failed clause')
    return value


def witness_request(report, spec):
    witness = report.get('counterexample')
    require(isinstance(witness, dict) and 'object_request' in witness, 'Missing typed witness discriminator')
    obj = witness['object_request']
    if obj is None:
        row = dict(id='witness', username=witness.get('principal'), groups=witness.get('identity_groups'), operation=witness.get('action'), resourceRequest=False, path=witness.get('path'))
    else:
        require(isinstance(obj, dict) and set(obj) == {'namespace', 'resource_kind', 'name'} and obj['resource_kind'] in KINDS, 'Invalid resource witness')
        group, resource, sub, _ = KINDS[obj['resource_kind']]
        row = dict(id='witness', username=witness.get('principal'), groups=witness.get('identity_groups'), operation=witness.get('action'),
            apiGroup=group, resource=resource, subresource=sub, namespace=obj['namespace'], name=obj['name'], resourceRequest=True)
    validate_request(row, {i['username']: i['groups'] for i in spec['context']['identities']}, spec['custom_resources'])
    grants = witness.get('granting_rules')
    require(strings(grants, nonempty=True) and len(set(grants)) == len(grants), 'Invalid grant evidence')
    if row['operation'] in PUT_OPERATIONS+apply.NEW_OPERATIONS:
        first = 'update' if row['operation'] in PUT_OPERATIONS else 'patch'
        prefixes = [first+': '] + (['create: '] if row['operation'].endswith('-missing') else [])
        for grant_id in grants:
            require(any(grant_id.startswith(p) and len(grant_id) > len(p) for p in prefixes), 'Wrong compound grant prefix')
        if grants:
            require(all(any(g.startswith(p) for g in grants) for p in prefixes), 'Missing compound grant stage')
    return row


def audit_witness(report, case, comparison=False):
    row, spec = witness_request(report, case['contract']), case['contract']
    selected = report.get('clause')
    require(isinstance(selected, dict), 'Missing clause')
    if comparison:
        require(selected.get('kind') == 'must_preserve' and selected.get('name') == 'preservation-outside-change-scope', 'Wrong preservation obligation')
        require(not any(scope_matches(s, row) for s in spec['change_scope']), 'Witness inside approved changes')
        wanted = case['preservation']
        kind = report['counterexample']['object_request']['resource_kind'] if row['resourceRequest'] else 'non_resource'
        require(kind == wanted['kind'] and row['operation'] == wanted['operation'] and row['username'] == wanted['user'], 'Wrong preservation witness dimensions')
    else:
        clauses = [c for c in spec['clauses'] if c['name'] == selected.get('name')]
        require(len(clauses) == 1 and clauses[0]['name'] == case['failed'] and clauses[0]['kind'] == selected.get('kind') and scope_matches(clauses[0], row), 'Witness outside failed clause')
    return row


def rejection_requests():
    rows = []
    for path in ['/api/v1/pods', '/apis/apps/v1/deployments', '//healthz', '/a//b', '/a/./b', '/a/../b',
                 '/a%2fb', '/healthz?verbose', '/healthz#fragment', 'healthz', '/white space', '/é']:
        rows.append(url_request(path, id_='bad-url-'+str(len(rows))))
    for label, changes in [('uppercase', dict(operation='GET')), ('extra-resource', dict(resource='pods')),
                           ('wrong-kind', dict(resourceRequest=0)), ('wrong-groups', dict(groups=['other']))]:
        rows.append(dict(url_request(id_=label), **changes))
    for group, resource, namespaced in NEW_BASES:
        ns = 'team-a' if namespaced else ''
        if resource == 'namespaces': ns = 'settings'
        rows.append(request(group, resource, operation='apply-missing', namespace=ns, id_='new-ssa-'+resource+'-'+group))
    for label, changes in [('namespace-empty', dict(namespace='')), ('namespace-different', dict(namespace='team-b')),
                           ('namespace-dot-name', dict(namespace='a.b', name='a.b'))]:
        rows.append(dict(request(resource='namespaces', namespace='team-a', name='team-a', id_=label), **changes))
    rows.append(request(resource='namespaces', operation='list', namespace='team-a', name='', id_='namespace-list-local'))
    rows.append(request(resource='namespaces', operation='create', namespace='', name='settings', id_='namespace-create-named'))
    for label, changes in [('custom-cluster-namespace', dict(resource='clusterwidgets', namespace='team-a')),
                           ('custom-unreviewed', dict(resource='otherwidgets')), ('custom-extra-subresource', dict(subresource='exec')),
                           ('custom-ssa', dict(operation='apply-missing'))]:
        rows.append(dict(request(group='widgets.example.test', resource='widgets', id_=label), **changes))
    rows.append(request(resource='pods', operation='update-missing', id_='pod-put-create'))
    return rows


def legacy_rejections():
    seen, result = set(), []
    old_classes = {(g, r, s, op) for g, r, s, _, operations in apply.CATALOGUE for op in operations}
    for row in matrix_requests():
        key = (row['apiGroup'], row['resource'], row['subresource'], row['operation']) if row['resourceRequest'] else ('url', row['operation'])
        if key in old_classes or key in seen: continue
        seen.add(key)
        result.append(row)
    return result


def planned_inputs():
    inputs = {'contract.json': encoded(contract()), 'legacy-contract.json': encoded(apply.contract()),
        'catalogue.json': encoded(CATALOGUE), 'matrix/requests.json': encoded(matrix_requests()),
        'rejections/requests.json': encoded(rejection_requests()), 'rejections/legacy.json': encoded(legacy_rejections()),
        'native-linkage.json': encoded(LINKAGE)}
    for case in matrix_cases():
        for key in ['snapshot', 'expected']: inputs['matrix/'+case['id']+'/'+key+'.json'] = encoded(case[key])
    for case in contract_cases():
        for key in ['contract', 'snapshot', 'baseline']:
            if case[key] is not None: inputs['contracts/'+case['id']+'/'+key+'.json'] = encoded(case[key])
        inputs['contracts/'+case['id']+'/expected.json'] = encoded({key: case[key] for key in ['expected', 'failed', 'comparison', 'preservation']})
    return inputs


def source_provenance(module_metadata):
    metadata = read_json(module_metadata)
    roots = {'kubernetes': Path(metadata['Dir']), 'apiserver': Path(metadata['Dir']).parent/'apiserver@v0.34.0'}
    pins = read_json(HERE/'source-pins.json')
    require(isinstance(pins, dict) and set(pins) == set(SOURCE_FILES), 'Wrong source modules')
    result = {}
    for module, entries in pins.items():
        require(isinstance(entries, dict) and set(entries) == set(SOURCE_FILES[module]), 'Wrong source inventory')
        for relative, sha in entries.items():
            require(isinstance(relative, str) and not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Unsafe source path')
            path = roots[module]/relative
            require(isinstance(sha, str) and digest(path) == sha, 'Upstream source differs: '+str(path))
            result[str(path)] = sha
    return result


def planned_counts(native_only=False):
    rows, cases = matrix_requests(), contract_cases()
    return dict(matrix_comparisons=len(rows)*len(matrix_cases()),
        contract_native_checks=len(rows)*sum(2 if c['baseline'] is not None else 1 for c in cases),
        rejected_requests=0 if native_only else len(rejection_requests()),
        legacy_rejected_requests=0 if native_only else len(legacy_rejections()),
        contract_witness_replays=0 if native_only else sum(c['expected'] == 'violated' for c in cases),
        preservation_witness_replays=0 if native_only else sum(c['comparison'] == 'violated' for c in cases))


def audit_completion(result, native_only=False):
    require(result.get('failures') == [] and result.get('native_only') is native_only, 'Wrong completion mode/failures')
    for key, expected in planned_counts(native_only).items():
        require(type(result.get(key)) is int and result[key] == expected, 'Incomplete counter: '+key)
    expected_cases = {'matrix/'+case['id']: dict(matrix_comparisons=len(matrix_requests())) for case in matrix_cases()}
    for case in contract_cases():
        entry = dict(native_contract=case['expected'], native_comparison=case['comparison'])
        if not native_only:
            entry['contract'] = case['expected']
            if case['baseline'] is not None: entry['comparison'] = case['comparison']
        expected_cases['contracts/'+case['id']] = entry
    require(encoded(result.get('cases')) == encoded(expected_cases), 'Incomplete case inventory')
    for flag in ['inputs_unchanged', 'binaries_unchanged', 'native_linkage_verified']:
        require(result.get(flag) is True, 'Unverified provenance: '+flag)


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
            'Synthetic frozen hypotheses over static snapshots, not a deployed-cluster benchmark or owner intent.',
            'Initial RBAC attribute classes do not establish installed routes, object validity, or API success; Namespace deletecollection is a deliberate example.',
            'Custom resource scope and subresources are trusted frozen catalogue inputs, not discovered from policies or arbitrary custom API behavior.',
            'PUT uses native RequestInfo/authorization/UpdateResource/strategies/Store with fixture-only Get and native dryRun=All.',
            'Service allocation hooks, admission, request body effects, storage races and real object existence are outside conditional authorization claims.',
            'Nonresource URLs use a canonical path subset; resource/nonresource classification comes from the pinned API server.',
            'Native NoOpinion is not final denial under arbitrary authorizer chains.',
            'Finite native/concrete/SMT agreement and witness replay are not a universal correctness proof.'])
    save(args.output, result)
    try:
        result['reference'] = module_provenance(args.module_metadata)
        result['upstream_source_sha256'] = source_provenance(args.module_metadata)
        inputs = planned_inputs()
        audit_pins(inputs, read_json(HERE/'inputs.json'))
        require((HERE/'contract.json').read_bytes() == inputs['contract.json'], 'Runnable contract differs')
        artifacts = args.output.parent/'artifacts'
        for key, value in inputs.items():
            path = artifacts/key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            result['input_sha256'][str(path)] = digest(path)
        source_dir = Path(__file__).resolve().parent
        source_paths = [Path(__file__), HERE/'generate.py', HERE/'inputs.json', HERE/'contract.json', HERE/'source-pins.json', args.module_metadata,
            source_dir/'test_coverage_runner.py'] + [source_dir/name for name in ['run.py', 'run_apply.py', 'run_resources.py', 'run_scopes.py',
                'run_subresources.py', 'run_collection_writes.py', 'run_write_access.py', 'run_read_access.py', 'oracle/go.mod', 'oracle/go.sum', 'oracle/module-pins.json']]
        result['source_sha256'] = {str(path): digest(path) for path in source_paths+sorted((source_dir/'oracle').glob('*.go'))}
        binaries, z3 = [args.reference], None
        if not args.native_only:
            require(args.model is not None and args.soundcheck is not None, 'Full comparison requires model and CLI')
            z3 = shutil.which(args.z3); require(z3 is not None, 'Z3 is required')
            binaries += [args.model, args.soundcheck, Path(z3)]
        result['binary_sha256'] = {str(path): digest(path) for path in binaries}
        save(args.output.parent/'before-execution.json', result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-coverage-z3-') as temporary:
            environment = dict(os.environ)
            if z3 is not None:
                Path(temporary, 'z3').symlink_to(Path(z3).resolve())
                environment['PATH'] = temporary+os.pathsep+environment.get('PATH', '')
            result['native_linkage'] = audit_linkage(execute([args.reference, '--coverage-reference-info'], args.output.parent/'native-linkage.json', environment))
            result['native_linkage_verified'] = True
            def native(manifest, rows, folder, label, expected=None):
                observed = {}
                for mode, selected in [('urls', [r for r in rows if r['operation'] not in apply.NEW_OPERATIONS+PUT_OPERATIONS]),
                    ('apply', [r for r in rows if r['operation'] in apply.NEW_OPERATIONS]),
                    ('put', [r for r in rows if r['operation'] in PUT_OPERATIONS])]:
                    if not selected: continue
                    path = folder/(label+'-'+mode+'-requests.json')
                    save(path, [as_url(r) for r in selected] if mode == 'urls' else selected)
                    option = {'urls': '--coverage-urls', 'apply': '--apply-reference', 'put': '--put-reference'}[mode]
                    execution = execute([args.reference, option, manifest, path], folder/(label+'-'+mode+'-reference.json'), environment)
                    audit = {'urls': audit_native_urls, 'apply': apply.audit_native, 'put': audit_native_put}[mode]
                    values = audit(execution, selected, expected)
                    require(not set(values).intersection(observed), 'Native partitions overlap')
                    observed.update(values)
                require(set(observed) == {r['id'] for r in rows}, 'Native partitions incomplete')
                return observed
            def agree(manifest, spec_path, rows, folder, label, expected=None):
                spec = read_json(spec_path)
                for row in rows: validate_request(row, custom=spec['custom_resources'])
                observed = native(manifest, rows, folder, label, expected)
                if not args.native_only:
                    path = folder/(label+'-model-requests.json'); save(path, rows)
                    model = execute([args.model, manifest, spec_path, path], folder/(label+'-model.json'), environment)
                    concrete = decisions(model, rows, 'model')
                    symbolic = smt_decisions(model, rows, folder, label, z3, environment)
                    require(observed == concrete == symbolic, 'Native/concrete/SMT mismatch: '+label)
                return observed
            rows = matrix_requests()
            for row in rows: validate_request(row)
            for case in matrix_cases():
                folder = artifacts/'matrix'/case['id']
                agree(folder/'snapshot.json', artifacts/'contract.json', rows, folder, 'matrix', case['expected'])
                result['matrix_comparisons'] += len(rows)
                result['cases']['matrix/'+case['id']] = dict(matrix_comparisons=len(rows))
                print(case['id']+': frozen/native'+('' if args.native_only else '/concrete/SMT')+' agree', flush=True)
                save(args.output, result)
            for case in contract_cases():
                folder = artifacts/'contracts'/case['id']
                spec_path, manifest, spec = folder/'contract.json', folder/'snapshot.json', case['contract']
                observed = native(manifest, rows, folder, 'finite')
                failed = []
                for selected in spec['clauses']:
                    points = [r for r in rows if scope_matches(selected, r)]
                    require(points, 'Finite corpus does not inhabit clause '+case['id']+'/'+selected['name'])
                    wanted = 'Allow' if selected['kind'] == 'must_allow' else 'NoOpinion'
                    if any(observed[r['id']] != wanted for r in points): failed.append(selected['name'])
                require(bool(failed) == (case['expected'] == 'violated'), 'Native contract differs: '+case['id'])
                if failed: require(failed[0] == case['failed'], 'Unexpected failing native clause: '+case['id'])
                result['contract_native_checks'] += len(rows)
                if case['baseline'] is not None:
                    prior = native(folder/'baseline.json', rows, folder, 'finite-before')
                    changed = [r for r in rows if prior[r['id']] != observed[r['id']] and not any(scope_matches(s, r) for s in spec['change_scope'])]
                    require(bool(changed) == (case['comparison'] == 'violated'), 'Native preservation differs: '+case['id'])
                    result['contract_native_checks'] += len(rows)
                def replay(report, comparison=False):
                    row = audit_witness(report, case, comparison)
                    after = agree(manifest, spec_path, [row], folder, 'witness-after')['witness']
                    require(bool(report['counterexample']['granting_rules']) == (after == 'Allow'), 'Witness grant evidence contradicts native decision')
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
                print(case['id']+': native requirements/preservation checked', flush=True)
                save(args.output, result)
            if not args.native_only:
                for category, rejected, spec_path, counter in [
                    ('outside', rejection_requests(), artifacts/'contract.json', 'rejected_requests'),
                    ('legacy', legacy_rejections(), artifacts/'legacy-contract.json', 'legacy_rejected_requests')]:
                    for i, row in enumerate(rejected):
                        label = category+'-'+str(i); path = artifacts/'rejections'/(label+'.json'); save(path, [row])
                        execution = execute([args.model, artifacts/'matrix/both-request-kinds/snapshot.json', spec_path, path], artifacts/'rejections'/(label+'-model.json'), environment)
                        require(decisions(execution, [row], 'model', allow_unsupported=True) is None, 'Outside-domain request received decision: '+label)
                        result[counter] += 1
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
