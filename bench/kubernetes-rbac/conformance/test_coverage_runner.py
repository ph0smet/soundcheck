#!/usr/bin/env python3
"""Adversarial consumers for frozen coverage evidence; no solver is invoked."""
import copy
import json
import unittest

import run_coverage as campaign
from test_apply_runner import native_execution as apply_execution


def url_execution(rows, choices):
    return dict(returncode=0, data=dict(schema_version=1, kind='rbac_coverage_url_authorization', valid=True,
        validation_errors=[], decisions=[dict(id=r['id'], decision=d, reason='', error='', attributes=campaign.expected_attributes(r),
            field_selector_error=False, label_selector_error=False) for r, d in zip(rows, choices)]))


def put_execution(rows, choices):
    changed = [dict(r, operation='apply-existing' if r['operation'] == 'update-existing' else 'apply-missing') for r in rows]
    value = apply_execution(changed, choices)
    value['data']['kind'] = 'rbac_put_authorization'
    for entry in value['data']['decisions']: entry['stages'][0]['attributes']['verb'] = 'update'
    return value


class CoverageEvidenceTests(unittest.TestCase):
    def test_frozen_inputs_and_all_operation_classes(self):
        campaign.audit_pins(campaign.planned_inputs(), campaign.read_json(campaign.HERE/'inputs.json'))
        rows = campaign.matrix_requests()
        self.assertEqual(len(rows), 4146)
        self.assertEqual(len(campaign.matrix_cases()), 24)
        self.assertEqual(len(campaign.contract_cases()), 47)
        classes = {(r['apiGroup'], r['resource'], r['subresource'], r['operation']) for r in rows if r['resourceRequest']}
        self.assertEqual(len(classes), 251)
        builtin = {k for k in classes if not k[0].endswith('.example.test')}
        self.assertEqual(len(builtin), 223)
        for row in rows: campaign.validate_request(row)
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError): campaign.validate_request(row)
        for key in classes:
            self.assertEqual({r['username'] for r in rows if r['resourceRequest'] and (r['apiGroup'], r['resource'], r['subresource'], r['operation']) == key}, set(campaign.IDENTITIES))
        for mutation in ['missing', 'changed', 'extra']:
            altered = campaign.planned_inputs()
            if mutation == 'missing': altered.pop('catalogue.json')
            elif mutation == 'changed': altered['matrix/empty/expected.json'] += b' '
            else: altered['extra.json'] = b'{}'
            with self.assertRaises(RuntimeError): campaign.audit_pins(altered, campaign.read_json(campaign.HERE/'inputs.json'))

    def test_namespace_and_custom_domains_are_independent_of_grants(self):
        campaign.validate_request(campaign.request(resource='namespaces', namespace='team-a', name='team-a'))
        campaign.validate_request(campaign.request(resource='namespaces', operation='list', namespace='', name='a.b'))
        for mutation in [dict(namespace=''), dict(namespace='team-b'), dict(name='a.b', namespace='a.b')]:
            row = dict(campaign.request(resource='namespaces', namespace='team-a', name='team-a'), **mutation)
            with self.assertRaises(RuntimeError): campaign.validate_request(row)
        custom = campaign.request(group='widgets.example.test', resource='widgets')
        campaign.validate_request(custom)
        with self.assertRaises(RuntimeError): campaign.validate_request(custom, custom=[])
        altered = copy.deepcopy(campaign.CUSTOM); altered[0]['scope'] = 'Cluster'
        with self.assertRaises(RuntimeError): campaign.validate_request(custom, custom=altered)
        campaign.validate_request(campaign.request(resource='services', operation='update-missing'))
        with self.assertRaises(RuntimeError): campaign.validate_request(campaign.request(resource='services', subresource='status', operation='update-missing'))

    def test_url_domain_and_request_kind_separation(self):
        for path in campaign.URL_PATHS: self.assertTrue(campaign.nonresource_path(path), path)
        for path in ['/api/v1/pods', '/apis/apps/v1/deployments', '/a//b', '/a/../b', '/a%2fb', '/a?b', '/a#b', '/a*b']:
            self.assertFalse(campaign.nonresource_path(path), path)
        url = campaign.url_request()
        resource = campaign.request()
        self.assertTrue(campaign.scope_matches(campaign.url_scope(path='/health', prefix=True), url))
        self.assertFalse(campaign.scope_matches(campaign.scope(), url))
        self.assertFalse(campaign.scope_matches(campaign.url_scope(path='/', prefix=True), resource))
        self.assertEqual(campaign.as_url(campaign.request(resource='namespaces', namespace='team-a', name='team-a'))['url'], '/api/v1/namespaces/team-a')
        self.assertEqual(campaign.as_url(campaign.request(resource='namespaces', namespace='', name='team-a', operation='list'))['url'], '/api/v1/namespaces?fieldSelector=metadata.name%3Dteam-a')

    def test_native_url_attribute_and_inventory_corruption(self):
        rows = [campaign.url_request(id_='url'), campaign.request(resource='namespaces', namespace='team-a', name='team-a', id_='namespace')]
        good = url_execution(rows, ['Allow', 'NoOpinion'])
        self.assertEqual(campaign.audit_native_urls(good, rows), {'url': 'Allow', 'namespace': 'NoOpinion'})
        for mutation in ['exit', 'schema', 'kind', 'valid', 'errors', 'missing', 'duplicate', 'id', 'decision', 'error', 'field-error', 'label-error',
            'path', 'namespace', 'name', 'resource', 'apiGroup', 'apiVersion', 'subresource', 'verb', 'username', 'groups', 'resourceRequest', 'extra-attribute']:
            value = copy.deepcopy(good); result = value['data']; entry = result['decisions'][0]
            if mutation == 'exit': value['returncode'] = False
            elif mutation == 'schema': result['schema_version'] = True
            elif mutation == 'kind': result['kind'] = 'rbac_request_url_authorization'
            elif mutation == 'valid': result['valid'] = 1
            elif mutation == 'errors': result['validation_errors'] = ['failed']
            elif mutation == 'missing': result['decisions'].pop()
            elif mutation == 'duplicate': result['decisions'][1] = copy.deepcopy(entry)
            elif mutation == 'id': entry['id'] = 'wrong'
            elif mutation == 'decision': entry['decision'] = 'Deny'
            elif mutation == 'error': entry['error'] = 'unresolved reference'
            elif mutation == 'field-error': entry['field_selector_error'] = True
            elif mutation == 'label-error': entry['label_selector_error'] = 0
            elif mutation == 'groups': entry['attributes']['groups'] = ['invented']
            elif mutation == 'resourceRequest': entry['attributes']['resourceRequest'] = 0
            elif mutation == 'extra-attribute': entry['attributes']['extra'] = True
            else: entry['attributes'][mutation] = 'wrong'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_native_urls(value, rows)
        with self.assertRaises(RuntimeError): campaign.audit_native_urls(good, rows, {'url': dict(decision='NoOpinion', stages=['NoOpinion']), 'namespace': dict(decision='NoOpinion', stages=['NoOpinion'])})

    def test_native_put_cannot_fabricate_or_drop_stages(self):
        row = campaign.request(resource='services', operation='update-missing')
        for choices in [['NoOpinion'], ['Allow', 'NoOpinion'], ['Allow', 'Allow']]:
            campaign.audit_native_put(put_execution([row], [choices]), [row])
        for choices in [['NoOpinion', 'Allow'], ['Allow']]:
            with self.assertRaises(RuntimeError): campaign.audit_native_put(put_execution([row], [choices]), [row])
        good = put_execution([row], [['Allow', 'Allow']])
        for mutation in ['kind', 'initial', 'create', 'name', 'namespace', 'path', 'reads', 'status', 'extra', 'error']:
            value = copy.deepcopy(good); entry = value['data']['decisions'][0]
            if mutation == 'kind': value['data']['kind'] = 'rbac_apply_authorization'
            elif mutation == 'initial': entry['stages'][0]['attributes']['verb'] = 'patch'
            elif mutation == 'create': entry['stages'][1]['attributes']['verb'] = 'update'
            elif mutation in ['name', 'namespace', 'path']: entry['stages'][1]['attributes'][mutation] = 'wrong'
            elif mutation == 'reads': entry['storage_reads'] = 0
            elif mutation == 'status': entry['http_status'] = 500
            elif mutation == 'extra': entry['stages'].append(copy.deepcopy(entry['stages'][1]))
            else: entry['stages'][1]['error'] = 'failure'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_native_put(value, [row])

    def test_report_freezes_custom_catalogue_url_and_resource_kinds(self):
        spec = campaign.contract([campaign.url_clause('required', 'must_allow'), campaign.clause('forbidden', 'must_not_grant', resource='secrets')])
        proof = dict(returncode=0, data=dict(schema_version=10, result='proved', property='kubernetes-rbac-access',
            assurance=dict(profile=campaign.PROFILE, status='within_profile', findings=[]), frozen_spec=dict(schema_version=9, kind=spec['kind'], canonical=json.dumps(spec)), clause=None, counterexample=None))
        campaign.audit_report(proof, spec, 'proved')
        for mutation in ['exit', 'profile', 'schema', 'custom-scope', 'custom-removal', 'url-selector', 'kind', 'identity']:
            value = copy.deepcopy(proof); fixed = copy.deepcopy(spec)
            if mutation == 'exit': value['returncode'] = False
            elif mutation == 'profile': value['data']['assurance']['profile'] = campaign.apply.PROFILE
            elif mutation == 'schema': value['data']['schema_version'] = 9
            else:
                if mutation == 'custom-scope': fixed['custom_resources'][0]['scope'] = 'Cluster'
                elif mutation == 'custom-removal': fixed['custom_resources'].clear()
                elif mutation == 'url-selector': fixed['clauses'][0]['paths'] = {'prefix': '/healthz'}
                elif mutation == 'kind': fixed['clauses'][0]['request_kind'] = 'resource'
                else: fixed['context']['identities'][0]['groups'] = ['extra']
                value['data']['frozen_spec']['canonical'] = json.dumps(fixed)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_report(value, spec, 'proved')

    def test_witness_discriminators_and_changed_scopes(self):
        spec = campaign.contract()
        url = dict(counterexample=dict(principal='ops', identity_groups=['operators'], action='get', path='/metrics', object_request=None, granting_rules=[]),
            clause=dict(name='preservation-outside-change-scope', kind='must_preserve'))
        case = next(c for c in campaign.contract_cases() if c['id'] == 'preserve-unmentioned-url')
        campaign.audit_witness(url, case, True)
        for mutation in ['missing-object', 'resource-path', 'groups', 'action', 'approved']:
            value = copy.deepcopy(url); changed = copy.deepcopy(case)
            if mutation == 'missing-object': del value['counterexample']['object_request']
            elif mutation == 'resource-path': value['counterexample']['path'] = '/api/v1/pods'
            elif mutation == 'groups': value['counterexample']['identity_groups'] = []
            elif mutation == 'action': value['counterexample']['action'] = 'list'
            else: changed['contract']['change_scope'] = [campaign.url_scope(path='/metrics', subject='ops')]
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_witness(value, changed, True)
        put = dict(counterexample=dict(principal='app', identity_groups=[], action='update-missing', object_request=dict(resource_kind='services', namespace='team-a', name='settings'), granting_rules=['update: original', 'create: second']))
        campaign.witness_request(put, spec)
        for grants in [['update: original'], ['patch: original', 'create: second'], ['update: ', 'create: second']]:
            changed = copy.deepcopy(put); changed['counterexample']['granting_rules'] = grants
            with self.assertRaises(RuntimeError): campaign.witness_request(changed, spec)

    def test_linkage_and_native_strategy_scopes_are_strict(self):
        versions = {'kubernetes': 'v1.34.0', 'apiserver': 'v0.34.0', 'api': 'v0.34.0', 'apimachinery': 'v0.34.0'}
        functions = {label: dict(function='k8s.io/'+module+'/'+function, file='k8s.io/'+module+'@'+versions[module]+'/'+source, line=line)
            for label, (module, source, line, function) in campaign.LINKAGE.items()}
        good = dict(returncode=0, data=dict(schema_version=1, kind='rbac_coverage_native_linkage', go_version='go1.24.0',
            modules={'k8s.io/'+m: v for m, v in versions.items()}, functions=functions,
            resource_scopes={r+('.'+g if g else ''): ns for g, r, ns in campaign.NEW_BASES}))
        campaign.audit_linkage(good)
        for mutation in ['module', 'function', 'line', 'file', 'missing', 'scope', 'bool-scope']:
            value = copy.deepcopy(good)
            if mutation == 'module': value['data']['modules']['k8s.io/apiserver'] = 'v0.35.0'
            elif mutation == 'missing': value['data']['functions'].pop('request-classifier')
            elif mutation == 'scope': value['data']['resource_scopes']['namespaces'] = True
            elif mutation == 'bool-scope': value['data']['resource_scopes']['namespaces'] = 0
            else: value['data']['functions']['update-handler'][mutation] = 'wrong'
            with self.assertRaises(RuntimeError): campaign.audit_linkage(value)

    def test_completion_rejects_missing_cases_or_counts(self):
        result = dict(failures=[], native_only=True, **campaign.planned_counts(True), inputs_unchanged=True,
            binaries_unchanged=True, native_linkage_verified=True, cases={})
        result['cases'] = {'matrix/'+c['id']: dict(matrix_comparisons=len(campaign.matrix_requests())) for c in campaign.matrix_cases()}
        result['cases'].update({'contracts/'+c['id']: dict(native_contract=c['expected'], native_comparison=c['comparison']) for c in campaign.contract_cases()})
        campaign.audit_completion(result, True)
        for mutation in ['count', 'case', 'mode', 'hashes', 'linkage']:
            value = copy.deepcopy(result)
            if mutation == 'count': value['matrix_comparisons'] = 0
            elif mutation == 'case': value['cases'].pop(next(iter(value['cases'])))
            elif mutation == 'mode': value['native_only'] = False
            elif mutation == 'hashes': value['inputs_unchanged'] = False
            else: value['native_linkage_verified'] = False
            with self.assertRaises(RuntimeError): campaign.audit_completion(value, True)


if __name__ == '__main__':
    unittest.main()
