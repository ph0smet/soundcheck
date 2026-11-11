#!/usr/bin/env python3
"""Adversarial checks for schema-v3 conformance; no solver or cluster needed."""
import copy
import json
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from run_read_access import validate_contract as validate_read_contract
from run_read_access import validate_request as validate_read_request
from run_write_access import (PROFILE, normalize_contract, older_contract_controls, request_attributes, request_url,
                              scope_matches, validate_contract, validate_report, validate_request,
                              validate_url_result, witness_request)


class WriteAccessChecks(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parent.parent/'write-access/contracts/write-access.json'
        self.contract = json.loads(path.read_text())
        self.identities = validate_contract(self.contract)
        self.request = {'id': 'witness', **self.contract['context']['identities'][0],
                        'verb': 'patch', 'apiGroup': '', 'resource': 'secrets', 'namespace': 'payments',
                        'name': 'token', 'resourceRequest': True, 'subresource': ''}
        url = request_url(self.request)
        self.url_case = {**url, 'expected_attributes': request_attributes(self.request, urlsplit(url['url']).path),
                         'field_selector_error': False, 'label_selector_error': False}
        self.url_result = {'returncode': 0, 'data': {'schema_version': 1,
            'kind': 'rbac_request_url_authorization', 'valid': True, 'validation_errors': [], 'decisions': [
                {'id': 'witness', 'decision': 'Allow', 'reason': 'grant', 'error': '',
                 'attributes': self.url_case['expected_attributes'], 'field_selector_error': False,
                 'label_selector_error': False}]}}
        self.report = {'returncode': 3, 'data': {'result': 'violated', 'schema_version': 10,
            'assurance': {'profile': PROFILE, 'status': 'within_profile'},
            'frozen_spec': {'schema_version': 3, 'kind': self.contract['kind'], 'canonical': json.dumps(self.contract)},
            'counterexample': {'principal': self.request['username'], 'identity_groups': self.request['groups'],
                              'action': 'patch', 'object_request': {'namespace': 'payments', 'resource_kind': 'secrets', 'name': 'token'},
                              'granting_rules': ['opaque-grant-label']}}}

    def test_named_write_methods_are_distinct_and_replayable(self):
        for verb, method in [('update', 'PUT'), ('patch', 'PATCH'), ('delete', 'DELETE')]:
            request = {**self.request, 'verb': verb}
            validate_request(request, self.identities)
            self.assertEqual(request_url(request)['method'], method)
            self.assertEqual(request_url(request)['url'], '/api/v1/namespaces/payments/secrets/token')
        self.assertEqual(validate_url_result(self.url_result, [self.url_case]), {'witness': 'Allow'})
        self.assertEqual(witness_request(validate_report(self.report, self.contract, 'violated'), self.identities), self.request)

    def test_old_validator_and_contract_never_gain_writes(self):
        for verb in ['update', 'patch', 'delete']:
            with self.subTest(verb=verb), self.assertRaises(RuntimeError):
                validate_read_request({**self.request, 'verb': verb}, self.identities)
        with self.assertRaises(RuntimeError):
            validate_read_contract(self.contract)
        changed = copy.deepcopy(self.contract)
        changed['schema_version'] = 2
        with self.assertRaises(RuntimeError):
            validate_contract(changed)
        with self.assertRaises(RuntimeError):
            validate_read_contract(changed)

    def test_old_contract_controls_require_same_attrs_and_frozen_groups(self):
        path = Path(__file__).parent.parent/'read-access/contracts/read-access.json'
        contract = json.loads(path.read_text())
        writes = [{**self.request, 'id': verb, 'verb': verb} for verb in ['update', 'patch', 'delete']]
        control, actual = older_contract_controls(writes, contract)
        self.assertEqual(actual, writes)
        self.assertEqual(control, {**self.request, 'id': 'older-get-control', 'verb': 'get'})
        for change in [{'namespace': 'frontend'}, {'name': 'other'}, {'groups': []}]:
            changed = copy.deepcopy(writes)
            changed[1].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                older_contract_controls(changed, contract)
        with self.assertRaises(RuntimeError):
            older_contract_controls([{**r, 'groups': []} for r in writes], contract)
        with self.assertRaises(RuntimeError):
            older_contract_controls(writes[:-1], contract)

    def test_write_domain_requires_names_and_namespaces(self):
        for verb in ['update', 'patch', 'delete']:
            for change in [{'name': ''}, {'namespace': ''}, {'name': '*'}, {'name': 'Token'},
                           {'namespace': None}, {'name': None}, {'subresource': 'status'},
                           {'apiGroup': 'other'}, {'resource': 'pods'}, {'groups': []}, {'resourceRequest': 1}]:
                with self.subTest(verb=verb, change=change), self.assertRaises(RuntimeError):
                    validate_request({**self.request, 'verb': verb, **change}, self.identities)
        for verb in ['create', 'deletecollection', 'unsafe-delete-ignore-read-errors']:
            with self.subTest(verb=verb), self.assertRaises(RuntimeError):
                validate_request({**self.request, 'verb': verb}, self.identities)

    def test_collection_read_domain_remains_available_only_to_reads(self):
        for verb in ['list', 'watch']:
            request = {**self.request, 'verb': verb, 'name': '', 'namespace': ''}
            validate_request(request, self.identities)
            self.assertEqual(request_url(request)['method'], 'GET')
            self.assertTrue(request_url(request)['url'].startswith('/api/v1/secrets'))

    def test_write_contract_cannot_select_empty_or_all_namespace_scope(self):
        for change in [{'namespace': None}, {'namespace': ''}, {'names': ['']}, {'names': ['*']},
                       {'names': []}, {'names': ['x', 'x']}, {'verb': 'create'}, {'verb': 'deletecollection'}]:
            changed = copy.deepcopy(self.contract)
            changed['clauses'][3].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                validate_contract(changed)
        # names:null is all valid named objects for writes, not the empty Name.
        changed = copy.deepcopy(self.contract)
        changed['clauses'][3]['names'] = None
        validate_contract(changed)

    def test_projected_url_corruption_is_detected_before_decision_comparison(self):
        for key, value in [('verb', 'update'), ('verb', 'delete'), ('name', ''), ('namespace', ''),
                           ('resource', 'configmaps'), ('subresource', 'status'), ('apiGroup', 'apps'),
                           ('apiVersion', 'v2'), ('resourceRequest', 1), ('path', '/wrong')]:
            changed = copy.deepcopy(self.url_result)
            changed['data']['decisions'][0]['attributes'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                validate_url_result(changed, [self.url_case])
        changed = copy.deepcopy(self.url_result)
        changed['data']['decisions'] *= 2
        with self.assertRaises(RuntimeError):
            validate_url_result(changed, [self.url_case])

    def test_frozen_write_verbs_are_not_collapsed_by_structural_projection(self):
        for verb in ['get', 'patch', 'delete']:
            changed = copy.deepcopy(self.contract)
            changed['clauses'][3]['verb'] = verb
            report = copy.deepcopy(self.report)
            report['data']['frozen_spec']['canonical'] = json.dumps(changed)
            with self.subTest(verb=verb), self.assertRaises(RuntimeError):
                validate_report(report, self.contract, 'violated')
        for profile in ['kubernetes-rbac-v1.34-get-v3', 'kubernetes-rbac-v1.34-read-v3',
                        'kubernetes-rbac-v1.34-read-write-v1']:
            report = copy.deepcopy(self.report)
            report['data']['assurance']['profile'] = profile
            with self.assertRaises(RuntimeError):
                validate_report(report, self.contract, 'violated')

    def test_out_of_scope_regression_compares_actual_verb(self):
        scope = self.contract['change_scope'][0]  # update payments Secrets
        self.assertTrue(scope_matches(scope, {**self.request, 'verb': 'update'}))
        for change in [{'verb': 'get'}, {'verb': 'patch'}, {'verb': 'delete'},
                       {'username': 'ops-auditor'}, {'namespace': 'frontend'}, {'resource': 'configmaps'}]:
            self.assertFalse(scope_matches(scope, {**self.request, 'verb': 'update', **change}))

    def test_invalid_counterexample_cannot_be_replayed_as_write(self):
        for field, value in [('name', ''), ('namespace', ''), ('resource_kind', 'pods')]:
            changed = copy.deepcopy(self.report['data'])
            changed['counterexample']['object_request'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                witness_request(changed, self.identities)
        changed = copy.deepcopy(self.report['data'])
        changed['counterexample']['action'] = 'deletecollection'
        with self.assertRaises(RuntimeError):
            witness_request(changed, self.identities)

    def test_canonical_preserves_ordered_clauses_and_exact_write_scope(self):
        reordered = copy.deepcopy(self.contract)
        reordered['context']['identities'].reverse()
        reordered['change_scope'].reverse()
        for identity in reordered['context']['identities']:
            identity['groups'].reverse()
        self.assertEqual(normalize_contract(reordered), normalize_contract(self.contract))
        reordered['clauses'].reverse()
        self.assertNotEqual(normalize_contract(reordered), normalize_contract(self.contract))


if __name__ == '__main__':
    unittest.main()
