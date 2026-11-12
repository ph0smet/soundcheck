#!/usr/bin/env python3
"""Frozen schema-6 collection-write experiments against Kubernetes v1.34.0.

Expected grants are literal experiments, not an RBAC reimplementation. Reuse
schema 5's frozen catalogue/builders, but keep the v6 request domain explicit.
The oracle observes initial authorization; bodies/selectors are not API effects.
"""
import argparse
import os
import shutil
import tempfile
from pathlib import Path

from run import (DNS_LABEL, EXIT_CODES, decisions, digest, execute,
                 module_provenance, read_json, require, save, smt_decisions,
                 strict_json, strings, valid_dns)
from run_scopes import normalized
import run_resources as resources
from run_resources import (CATALOGUE, KINDS, IDENTITIES, clause, scope, rule, grant,
                           snapshot, request, encoded, byte_hash, audit_pins,
                           scope_matches)

HERE = resources.HERE.parent/'collection-writes'
PROFILE = 'kubernetes-rbac-v1.34-collection-write-v1'
LEGACY_PROFILE = resources.PROFILE
NEW_VERBS = ['create', 'deletecollection']
VERBS = resources.VERBS + NEW_VERBS


def contract(clauses=None, changes=None, version=6):
    if version == 5:
        return resources.contract(clauses, () if changes is None else changes, version=5)
    if clauses is None:
        clauses = [clause('required-create', 'must_allow', resource='pods', verb='create', names={'empty': True}),
                   clause('required-read', 'must_allow', names=['settings']),
                   clause('forbidden-bulk-delete', 'must_not_grant', resource='pods', verb='deletecollection', names=None)]
    if changes is None:
        changes = [scope(resource='pods', verb='deletecollection', names={'empty': True})]
    return resources.contract(clauses, changes, version=version)


def matrix_requests():
    rows = resources.matrix_requests()
    for group, resource, namespaced in CATALOGUE:
        for verb in NEW_VERBS:
            for namespace in ['team-a', 'team-b'] if namespaced else ['']:
                for user in IDENTITIES:
                    rows.append(request(group, resource, verb, namespace, '', user, str(len(rows))))
    return rows


def matrix_cases():
    rows, cases = matrix_requests(), []

    def add(id_, items, allowed):
        cases.append(dict(id=id_, snapshot=snapshot(items),
                          expected={r['id']: 'Allow' if allowed(r) else 'NoOpinion' for r in rows}))

    app = lambda r: r['username'] == 'app'
    newer = lambda r: app(r) and r['verb'] in NEW_VERBS
    both = rule(('*',), ('*',), NEW_VERBS)
    add('empty-policy', [], lambda _: False)
    add('whole-wildcards', grant('all', [rule(('*',), ('*',), ['*'])]), app)
    add('create-only', grant('create', [rule(('*',), ('*',), ['create'])]), lambda r: app(r) and r['verb'] == 'create')
    add('bulk-delete-only', grant('bulk', [rule(('*',), ('*',), ['deletecollection'])]), lambda r: app(r) and r['verb'] == 'deletecollection')
    add('named-delete-is-distinct', grant('named', [rule(('*',), ('*',), ['delete'])]), lambda r: app(r) and r['verb'] == 'delete')
    add('role-binding-local-role', grant('local', [both], 'team-a', local_role=True), lambda r: newer(r) and r['namespace'] == 'team-a')
    add('role-binding-cluster-role', grant('local-cluster', [both], 'team-a'), lambda r: newer(r) and r['namespace'] == 'team-a')
    for group, id_ in [('', 'core'), ('apps', 'apps'), ('discovery.k8s.io', 'discovery')]:
        add(id_+'-group', grant(id_, [rule((group,), ('*',), NEW_VERBS)]), lambda r, g=group: newer(r) and r['apiGroup'] == g)
    add('exact-pods-wildcard-group', grant('pods', [rule(('*',), ('pods',), NEW_VERBS)]), lambda r: newer(r) and r['resource'] == 'pods')
    add('wrong-group-and-subresource', grant('wrong', [rule(('apps',), ('pods',), NEW_VERBS),
        rule(('extensions',), ('deployments',), NEW_VERBS), rule(('*',), ('*/status', 'pods/*'), NEW_VERBS)]), lambda _: False)
    add('explicit-empty-resourceNames', grant('explicit-empty', [rule(('*',), ('*',), ['*'], [])]), app)
    for names, id_ in [(['settings'], 'named'), ([''], 'empty'), (['*'], 'literal-star'), (['', 'settings'], 'mixed')]:
        add(id_+'-resourceNames', grant(id_, [rule(('*',), ('*',), ['*'], names)]), lambda r, n=names: app(r) and r['name'] in n)
    add('additive-grant', grant('restricted', [rule(('*',), ('*',), NEW_VERBS, ['settings'])])+
        grant('bypass', [rule(('apps',), ('deployments',), ['create'])], 'team-b'),
        lambda r: newer(r) and r['verb'] == 'create' and r['apiGroup'] == 'apps' and r['resource'] == 'deployments' and r['namespace'] == 'team-b')
    aggregate = grant('aggregate', [both])
    aggregate[0]['aggregationRule'] = dict(clusterRoleSelectors=[dict(matchLabels={'conformance.soundcheck/collection': 'true'})])
    leaf = grant('leaf', [both])[0]
    leaf['metadata']['labels'] = {'conformance.soundcheck/collection': 'true'}
    add('resolved-aggregate-new-verbs', [leaf]+aggregate, newer)
    group_grant = grant('operators', [both])
    group_grant[1]['subjects'] = [dict(kind='Group', apiGroup=resources.API, name='operators')]
    add('trusted-group-new-verbs', group_grant, lambda r: r['username'] == 'ops' and r['verb'] in NEW_VERBS)
    return cases


def contract_cases():
    cases = []

    def add(id_, spec, items, expected, failed=None, baseline=None, comparison=None, preservation=None):
        cases.append(dict(id=id_, contract=spec, snapshot=snapshot(items), expected=expected, failed=failed,
            baseline=None if baseline is None else snapshot(baseline), comparison=comparison, preservation=preservation))

    read = grant('reader', [rule(names=['settings'])], 'team-a')
    create = grant('creator', [rule(('',), ('pods',), ['create'])], 'team-a')
    bulk = grant('bulk-delete', [rule(('',), ('pods',), ['deletecollection'])], 'team-a')
    spec = contract()
    before = read+create+bulk
    repaired = read+create+bulk[:1]
    add('unsafe-bulk-delete', spec, before, 'violated', 'forbidden-bulk-delete')
    add('minimal-bulk-delete-repair', spec, repaired, 'proved', baseline=before, comparison='proved')
    add('required-create-lost-but-read-kept', spec, read+create[:1]+bulk[:1], 'violated', 'required-create')
    for names, id_, verdict in [(['settings'], 'object-name', 'violated'), (['*'], 'literal-star', 'violated'), ([''], 'empty-name', 'proved')]:
        add(id_+'-create-rule', spec, read+grant(id_, [rule(('',), ('pods',), ['create'], names)], 'team-a'),
            verdict, 'required-create' if verdict == 'violated' else None)
    add('name-restricted-bulk-delete-does-not-grant', spec, read+create+
        grant('restricted-bulk', [rule(('',), ('pods',), ['deletecollection'], ['settings'])], 'team-a'), 'proved')
    add('empty-name-bulk-delete-grants', spec, read+create+
        grant('empty-bulk', [rule(('',), ('pods',), ['deletecollection'], [''])], 'team-a'), 'violated', 'forbidden-bulk-delete')
    add('named-delete-does-not-grant-bulk-delete', spec, read+create+
        grant('named-delete', [rule(('',), ('pods',), ['delete'])], 'team-a'), 'proved')

    node = contract([clause('required-node-create', 'must_allow', resource='nodes', verb='create', namespace=None, names=None),
        clause('forbidden-node-bulk', 'must_not_grant', resource='nodes', verb='deletecollection', namespace=None, names={'empty': True})], [])
    add('node-cluster-create', node, grant('node-create', [rule(('',), ('nodes',), ['create'])]), 'proved')
    add('node-rolebinding-cannot-grant', node, grant('node-local', [rule(('',), ('nodes',), ['create'])], 'team-a'),
        'violated', 'required-node-create')
    selected = contract([clause('required-create-two-namespaces', 'must_allow', group='apps', resource='deployments',
                               verb='create', namespace={'include': ['team-b', 'team-a']}, names=None),
        clause('forbidden-outside-bulk', 'must_not_grant', group='apps', resource='deployments',
               verb='deletecollection', namespace={'exclude': ['team-a']}, names={'empty': True})], [])
    creators = sum([grant('deploy-'+ns, [rule(('apps',), ('deployments',), ['create'])], ns) for ns in ['team-a', 'team-b']], [])
    add('namespace-selectors', selected, creators, 'proved')
    add('outside-namespace-bulk-leak', selected, creators+grant('outside-bulk', [rule(('apps',), ('deployments',), ['deletecollection'])]),
        'violated', 'forbidden-outside-bulk')

    outside_create = scope(resource='pods', verb='create', namespace={'exclude': ['team-a']}, names=None)
    create_safety = contract([clause('required-local-create', 'must_allow', resource='pods', verb='create', names={'empty': True}),
        dict(name='forbidden-outside-create', kind='must_not_grant', **outside_create)], [outside_create])
    global_create = grant('global-creator', [rule(('',), ('pods',), ['create'])])
    add('outside-namespace-create-leak', create_safety, global_create, 'violated', 'forbidden-outside-create')
    add('outside-namespace-create-repair', create_safety, global_create[:1]+create, 'proved',
        baseline=global_create, comparison='proved')

    # Same requirements in both versions. Only the preservation universe changes.
    # The changed identity and resource do not appear in any contract clause.
    for group, resource, namespace, verb in [('', 'nodes', None, 'create'),
            ('discovery.k8s.io', 'endpointslices', 'team-b', 'deletecollection')]:
        extra = grant('ops-'+resource, [rule((group,), (resource,), [verb])], namespace, subject='ops')
        for version in [5, 6]:
            fixed = resources.contract(version=5)
            fixed['schema_version'] = version
            add(f'v{version}-unmentioned-{verb}', fixed, read+extra[:1], 'proved', baseline=read+extra,
                comparison='proved' if version == 5 else 'violated',
                preservation=dict(kind=resource if not group else resource+'.'+group, verb=verb, user='ops'))
    return cases


def validate_request(row, identities=IDENTITIES, version=6):
    require(type(version) is int and version in [5, 6], 'Unexpected campaign contract version')
    if version == 5 or row.get('verb') not in NEW_VERBS:
        resources.validate_request(row, identities, version=5)
        return
    require(isinstance(row, dict) and set(row) == {'id', 'username', 'groups', 'verb', 'apiGroup',
        'resource', 'namespace', 'name', 'resourceRequest', 'subresource'}, 'Unexpected request schema')
    require(isinstance(row['id'], str) and row['id'], 'Invalid request id')
    require(isinstance(row['username'], str) and row['username'] in identities, 'Unknown frozen identity')
    require(strings(row['groups'], nonempty=True) and len(set(row['groups'])) == len(row['groups']) and
            sorted(row['groups']) == sorted(identities[row['username']]), 'Identity groups differ')
    require(row['resourceRequest'] is True and row['subresource'] == '', 'Outside resource/subresource domain')
    selected = [entry for entry in CATALOGUE if entry[:2] == (row['apiGroup'], row['resource'])]
    require(len(selected) == 1, 'Unknown API group/resource pair')
    require(valid_dns(row['namespace'], 63, DNS_LABEL) if selected[0][2] else row['namespace'] == '',
            'Collection writes require a namespace, or empty namespace for Nodes')
    require(row['name'] == '', 'Collection writes require an empty authorization name')


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
    validate_request(row, {i['username']: i['groups'] for i in spec['context']['identities']}, spec['schema_version'])
    require(strings(witness.get('granting_rules'), nonempty=True) and
            len(set(witness['granting_rules'])) == len(witness['granting_rules']), 'Invalid witness grants')
    return row


def audit_report(execution, spec, expected, comparison=False):
    report = execution.get('data')
    require(isinstance(report, dict) and report.get('result') == expected and
            execution.get('returncode') == EXIT_CODES[expected], 'Unexpected report verdict/exit')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 10, 'Wrong report schema')
    require(report.get('property') == ('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'), 'Wrong property')
    assurance = report.get('assurance')
    require(isinstance(assurance, dict) and assurance.get('profile') == (PROFILE if spec['schema_version'] == 6 else LEGACY_PROFILE)
            and assurance.get('status') == 'within_profile' and assurance.get('findings') == [], 'Wrong assurance')
    frozen = report.get('frozen_spec')
    require(isinstance(frozen, dict) and type(frozen.get('schema_version')) is int and
            frozen['schema_version'] == spec['schema_version'] and frozen.get('kind') == spec['kind'] and
            isinstance(frozen.get('canonical'), str), 'Missing frozen spec identity')
    require(encoded(normalized(strict_json(frozen['canonical']))) == encoded(normalized(spec)), 'Frozen contract was changed')
    if expected != 'violated':
        require(report.get('counterexample') is None, 'Non-violation contains a witness')
    if expected == 'proved':
        require(report.get('clause') is None, 'Proof contains a failed clause')
    return report


def audit_witness(report, case, comparison=False):
    spec = case['contract']
    row = witness_request(report, spec)
    reported = report.get('clause')
    require(isinstance(reported, dict), 'Missing clause identity')
    if comparison:
        require(reported.get('kind') == 'must_preserve' and
                reported.get('name') == 'preservation-outside-change-scope', 'Wrong preservation obligation')
        require(not any(scope_matches(s, row) for s in spec['change_scope']), 'Witness inside approved changes')
        wanted = case['preservation']
        require(report['counterexample']['object_request']['resource_kind'] == wanted['kind'] and
                row['verb'] == wanted['verb'] and row['username'] == wanted['user'], 'Wrong preservation witness dimensions')
    else:
        selected = [c for c in spec['clauses'] if c['name'] == reported.get('name')]
        require(len(selected) == 1 and selected[0]['name'] == case['failed'] and
                selected[0]['kind'] == reported.get('kind') and scope_matches(selected[0], row), 'Witness outside expected clause')
    return row


def url_cases():
    rows = []

    def add(id_, method, url, group, resource, verb, namespace, name, supported=True, body=None,
            field_error=False, label_error=False, subresource=''):
        incoming = dict(id=id_, username='app', groups=[], method=method, url=url)
        if body is not None:
            incoming['body'] = body
        attrs = request(group, resource, verb, namespace, name, id_=id_)
        del attrs['id']
        attrs.update(apiVersion='v1', path=url.split('?', 1)[0], subresource=subresource)
        rows.append(dict(request=incoming, attributes=attrs, supported=supported,
                         field_selector_error=field_error, label_selector_error=label_error))

    for group, resource, namespaced in CATALOGUE:
        prefix = '/api/v1' if not group else '/apis/'+group+'/v1'
        base = prefix+('/namespaces/team-a' if namespaced else '')+'/'+resource
        ns = 'team-a' if namespaced else ''
        for label, body in [('missing', None), ('named', '{"metadata":{"name":"settings"}}'),
                            ('different', '{"metadata":{"name":"other"}}'),
                            ('generated', '{"metadata":{"generateName":"settings-"}}'), ('malformed', '{broken')]:
            add(resource+'-create-'+label, 'POST', base, group, resource, 'create', ns, '', body=body)
        add(resource+'-create-selector', 'POST', base+'?fieldSelector=metadata.name%3Dsettings', group, resource, 'create', ns, '')
        add(resource+'-bulk-delete', 'DELETE', base, group, resource, 'deletecollection', ns, '')
        add(resource+'-bulk-selected', 'DELETE', base+'?fieldSelector=metadata.name%3Dsettings', group, resource, 'deletecollection', ns, '')
        for query, verb in [('?fieldSelector=metadata.name%3Dsettings', 'list'), ('?watch=true&fieldSelector=metadata.name%3Dsettings', 'watch')]:
            add(resource+'-'+verb+'-selected', 'GET', base+query, group, resource, verb, ns, 'settings')
        add(resource+'-named-delete', 'DELETE', base+'/settings', group, resource, 'delete', ns, 'settings')
        add(resource+'-named-post-excluded', 'POST', base+'/settings', group, resource, 'create', ns, 'settings', False,
            body='{"metadata":{"name":"other"}}')
        if namespaced:
            for method, verb in [('POST', 'create'), ('DELETE', 'deletecollection')]:
                add(resource+'-all-namespaces-'+verb, method, prefix+'/'+resource, group, resource, verb, '', '', False)
    base = '/api/v1/namespaces/team-a/pods'
    add('bulk-malformed-field', 'DELETE', base+'?fieldSelector=metadata.name%3Dsettings%2Cbroken', '', 'pods', 'deletecollection', 'team-a', '', field_error=True)
    add('bulk-repeated-field', 'DELETE', base+'?fieldSelector=metadata.name%3Dsettings&fieldSelector=metadata.name%3Dother', '', 'pods', 'deletecollection', 'team-a', '')
    add('bulk-malformed-label', 'DELETE', base+'?labelSelector=broken%20in%20%28', '', 'pods', 'deletecollection', 'team-a', '', label_error=True)
    add('create-malformed-selectors-ignored', 'POST', base+'?fieldSelector=broken&labelSelector=broken%20in%20%28', '', 'pods', 'create', 'team-a', '')
    add('create-name-query-is-not-path-name', 'POST', base+'?name=settings', '', 'pods', 'create', 'team-a', '')
    add('create-subresource-excluded', 'POST', base+'/settings/exec', '', 'pods', 'create', 'team-a', 'settings', False, subresource='exec')
    return rows


def url_policies():
    return [('unrestricted', None), ('named', ['settings']), ('empty', ['']), ('literal-star', ['*'])]


def url_expected(names):
    return [dict(row, decision='Allow' if names is None or row['attributes']['name'] in names else 'NoOpinion') for row in url_cases()]


def audit_urls(execution, expected):
    value = execution.get('data')
    require(execution.get('returncode') == 0 and isinstance(value, dict) and type(value.get('schema_version')) is int and
            value['schema_version'] == 1 and value.get('kind') == 'rbac_request_url_authorization' and
            value.get('valid') is True and value.get('validation_errors') == [], 'Invalid native URL envelope')
    rows = value.get('decisions')
    require(isinstance(rows, list) and len(rows) == len(expected), 'Missing URL extraction rows')
    wanted = {row['request']['id']: row for row in expected}
    require(len(wanted) == len(expected), 'Duplicate planned URL id')
    actual = {}
    for row in rows:
        require(isinstance(row, dict) and row.get('id') in wanted and row['id'] not in actual, 'Duplicate/unexpected URL id')
        fixed = wanted[row['id']]
        require(encoded(row.get('attributes')) == encoded(fixed['attributes']) and row.get('decision') == fixed['decision'] and
                row.get('error') == '' and isinstance(row.get('reason'), str) and
                row.get('field_selector_error') is fixed['field_selector_error'] and
                row.get('label_selector_error') is fixed['label_selector_error'], 'Native URL evidence differs: '+row['id'])
        actual[row['id']] = row['attributes']
    return actual


def rejection_requests():
    valid = request('apps', 'deployments', 'create', name='')
    changes = [('create-named', {'name': 'settings'}), ('bulk-named', {'verb': 'deletecollection', 'name': 'settings'}),
        ('create-all-namespaces', {'namespace': ''}), ('bulk-all-namespaces', {'verb': 'deletecollection', 'namespace': ''}),
        ('node-namespaced', {'apiGroup': '', 'resource': 'nodes'}), ('unknown-group', {'apiGroup': 'extensions'}),
        ('qualified-resource', {'resource': 'deployments.apps'}), ('custom-resource', {'resource': 'widgets', 'apiGroup': 'example.test'}),
        ('namespace-resource', {'resource': 'namespaces', 'apiGroup': ''}), ('subresource', {'subresource': 'scale'}),
        ('non-resource', {'resourceRequest': False}), ('bad-namespace', {'namespace': 'UPPER'}), ('long-namespace', {'namespace': 'a'*64})]
    return [dict(valid, id=id_, **change) for id_, change in changes]


def planned_inputs():
    inputs = {'contract.json': encoded(contract()), 'legacy-contract.json': encoded(contract(version=5)),
              'matrix/requests.json': encoded(matrix_requests()), 'rejections/requests.json': encoded(rejection_requests())}
    for case in matrix_cases():
        for key in ['snapshot', 'expected']:
            inputs['matrix/'+case['id']+'/'+key+'.json'] = encoded(case[key])
    for case in contract_cases():
        for key in ['contract', 'snapshot', 'baseline']:
            if case[key] is not None:
                inputs['contracts/'+case['id']+'/'+key+'.json'] = encoded(case[key])
        inputs['contracts/'+case['id']+'/expected.json'] = encoded({k: case[k] for k in ['expected', 'failed', 'comparison', 'preservation']})
    for id_, names in url_policies():
        inputs['urls/'+id_+'/snapshot.json'] = encoded(snapshot(grant('url-global', [rule(('*',), ('*',), ['*'], names)])))
        inputs['urls/'+id_+'/requests.json'] = encoded([row['request'] for row in url_cases()])
        inputs['urls/'+id_+'/expected.json'] = encoded(url_expected(names))
    return inputs


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
        rejected_requests=0, legacy_rejected_requests=0, contract_witness_replays=0, preservation_witness_replays=0,
        cases={}, failures=[], input_sha256={}, limits=[
            'Frozen synthetic inputs and initial RBAC authorization only; no cluster/deployment contacted.',
            'Finite native/concrete/SMT agreement is not universal proof of implementation correctness.',
            'Body names and deletion selectors do not restrict these empty-name authorization requests.',
            'No route availability, body validity, API mutation, selected/deleted objects, admission or extra authorization claim.',
            'Schema 5 retains six verbs; schema 6 opts into create/deletecollection over the same eight resources.'])
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
        source_dir = Path(__file__).parent
        result['source_sha256'] = {str(path): digest(path) for path in [Path(__file__), HERE/'inputs.json', HERE/'contract.json', args.module_metadata]+
            [source_dir/name for name in ['run.py', 'run_scopes.py', 'run_write_access.py', 'run_read_access.py',
                                         'run_resources.py', 'oracle/go.mod', 'oracle/go.sum', 'oracle/module-pins.json']]+
            sorted((source_dir/'oracle').glob('*.go'))}
        z3 = shutil.which(args.z3)
        require(z3 is not None, 'Z3 is required')
        result['binary_sha256'] = {str(path): digest(path) for path in [args.reference, args.model, args.soundcheck, Path(z3)]}
        save(args.output, result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-collection-write-z3-') as temporary:
            Path(temporary, 'z3').symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=temporary+os.pathsep+os.environ.get('PATH', ''))

            def native(manifest, rows, folder, label):
                path = folder/(label+'-requests.json')
                save(path, rows)
                return decisions(execute([args.reference, manifest, path], folder/(label+'-reference.json'), environment), rows, 'reference')

            def agree(manifest, spec_path, rows, folder, label, expected=None):
                spec = read_json(spec_path)
                for row in rows:
                    validate_request(row, version=spec['schema_version'])
                upstream = native(manifest, rows, folder, label)
                model = execute([args.model, manifest, spec_path, folder/(label+'-requests.json')], folder/(label+'-model.json'), environment)
                concrete = decisions(model, rows, 'model')
                symbolic = smt_decisions(model, rows, folder, label, z3, environment)
                require(upstream == concrete == symbolic, 'Native/concrete/SMT mismatch: '+label)
                if expected is not None:
                    require(upstream == expected, 'Literal expected grants differ: '+label)
                return upstream

            rows = matrix_requests()
            for case in matrix_cases():
                folder = artifacts/'matrix'/case['id']
                agree(folder/'snapshot.json', artifacts/'contract.json', rows, folder, 'matrix', case['expected'])
                result['matrix_comparisons'] += len(rows)
                result['cases'][case['id']] = dict(matrix_comparisons=len(rows))
                print(case['id']+': literal/native/concrete/SMT agree', flush=True)
                save(args.output, result)

            for case in contract_cases():
                folder = artifacts/'contracts'/case['id']
                manifest, spec_path, spec = folder/'snapshot.json', folder/'contract.json', case['contract']
                finite = [row for row in rows if spec['schema_version'] == 6 or row['verb'] not in NEW_VERBS]
                observed = native(manifest, finite, folder, 'finite')
                failures = []
                for selected in spec['clauses']:
                    points = [row for row in finite if scope_matches(selected, row)]
                    require(points, 'Finite corpus does not inhabit clause '+selected['name'])
                    wanted = 'Allow' if selected['kind'] == 'must_allow' else 'NoOpinion'
                    if any(observed[row['id']] != wanted for row in points):
                        failures.append(selected['name'])
                require(bool(failures) == (case['expected'] == 'violated'), 'Finite native contract differs: '+case['id'])
                if failures:
                    require(failures[0] == case['failed'], 'Unexpected first native failing clause')
                result['contract_native_checks'] += len(finite)
                if case['baseline'] is not None:
                    prior = native(folder/'baseline.json', finite, folder, 'finite-before')
                    changed = [row for row in finite if prior[row['id']] != observed[row['id']] and
                               not any(scope_matches(selected, row) for selected in spec['change_scope'])]
                    require(bool(changed) == (case['comparison'] == 'violated'), 'Finite native preservation differs: '+case['id'])
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

                report = audit_report(execute([args.soundcheck, 'rbac', 'verify', manifest, '--contract', spec_path,
                    '--format', 'json'], folder/'verify.json', environment), spec, case['expected'])
                result['cases'][case['id']] = dict(contract=report['result'])
                if report['result'] == 'violated':
                    replay(report)
                if case['baseline'] is not None:
                    compared = audit_report(execute([args.soundcheck, 'rbac', 'compare', folder/'baseline.json', manifest,
                        '--contract', spec_path, '--format', 'json'], folder/'compare.json', environment), spec, case['comparison'], True)
                    result['cases'][case['id']]['comparison'] = compared['result']
                    if compared['result'] == 'violated':
                        replay(compared, True)
                print(case['id']+': '+str(result['cases'][case['id']]), flush=True)
                save(args.output, result)

            excluded = []
            for id_, names in url_policies():
                folder, fixed = artifacts/'urls'/id_, url_expected(names)
                extracted = audit_urls(execute([args.reference, '--request-urls', folder/'snapshot.json', folder/'requests.json'],
                                              folder/'reference.json', environment), fixed)
                supported = []
                for case in fixed:
                    attrs = dict(extracted[case['request']['id']])
                    del attrs['apiVersion'], attrs['path']
                    row = dict(attrs, id=case['request']['id'])
                    if case['supported']:
                        supported.append(row)
                    elif id_ == 'unrestricted':
                        excluded.append(row)
                agree(folder/'snapshot.json', artifacts/'contract.json', supported, folder, 'extracted',
                      {case['request']['id']: case['decision'] for case in fixed if case['supported']})
                result['url_comparisons'] += len(fixed)
                print('urls-'+id_+': native attributes and decisions agree', flush=True)

            def reject(row, spec_path, label):
                path = artifacts/'rejections'/(label+'.json')
                save(path, [row])
                model = execute([args.model, artifacts/'urls'/'unrestricted'/'snapshot.json', spec_path, path],
                    artifacts/'rejections'/(label+'-model.json'), environment)
                require(decisions(model, [row], 'model', allow_unsupported=True) is None, 'Outside-domain request received a decision: '+label)

            for row in rejection_requests()+excluded:
                reject(row, artifacts/'contract.json', row['id'])
                result['rejected_requests'] += 1
            for row in rows:
                if row['verb'] in NEW_VERBS:
                    reject(row, artifacts/'legacy-contract.json', 'v5-'+row['id'])
                    result['legacy_rejected_requests'] += 1
            for key in ['input_sha256', 'source_sha256', 'binary_sha256']:
                require(all(digest(Path(path)) == sha for path, sha in result[key].items()), key+' changed during execution')
            audit_pins(planned_inputs(), read_json(HERE/'inputs.json'))
            result.update(inputs_unchanged=True, binaries_unchanged=True, complete=True)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result['failures'].append(str(error))
    save(args.output, result)
    print({key: result[key] for key in ['complete', 'matrix_comparisons', 'url_comparisons', 'contract_native_checks',
        'rejected_requests', 'legacy_rejected_requests', 'contract_witness_replays', 'preservation_witness_replays', 'failures']})
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
