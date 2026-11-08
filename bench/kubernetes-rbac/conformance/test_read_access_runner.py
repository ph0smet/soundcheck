#!/usr/bin/env python3
"""Fail-closed protocol controls for read-access and URL witness comparison."""
import copy
import json
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from run_read_access import (PROFILE, normalize_contract, request_attributes, request_url,
                             scope_matches, validate_contract, validate_report,
                             validate_request, validate_url_result, witness_request)


class ReadAccessChecks(unittest.TestCase):
    def setUp(self):
        corpus = Path(__file__).parent.parent/'read-access'
        self.contract = json.loads((corpus/'contracts/read-access.json').read_text())
        self.identities = validate_contract(self.contract)
        identity = self.contract['context']['identities'][0]
        self.request = {'id': 'witness', **identity, 'verb': 'watch', 'apiGroup': '',
                        'resource': 'secrets', 'namespace': '', 'name': 'token',
                        'resourceRequest': True, 'subresource': ''}
        url = request_url(self.request)
        self.case = {**url, 'expected_attributes': request_attributes(self.request, urlsplit(url['url']).path),
                     'field_selector_error': False, 'label_selector_error': False}
        self.url_result = {'returncode': 0, 'data': {
            'schema_version': 1, 'kind': 'rbac_request_url_authorization', 'valid': True,
            'validation_errors': [], 'decisions': [{'id': 'witness', 'decision': 'Allow', 'error': '',
                'reason': 'upstream grant', 'attributes': self.case['expected_attributes'],
                'field_selector_error': False, 'label_selector_error': False}]}}
        self.report = {'returncode': 3, 'data': {
            'schema_version': 10, 'result': 'violated',
            'assurance': {'profile': PROFILE, 'status': 'within_profile'},
            'frozen_spec': {'schema_version': 2, 'kind': self.contract['kind'], 'canonical': json.dumps(self.contract)},
            'counterexample': {'principal': self.request['username'], 'identity_groups': self.request['groups'],
                'action': 'watch', 'object_request': {'namespace': '', 'resource_kind': 'secrets', 'name': 'token'},
                'granting_rules': ['opaque-binding-label']}}}

    def test_complete_protocol_and_named_collection_url(self):
        validate_request(self.request, self.identities)
        self.assertEqual(validate_url_result(self.url_result, [self.case]), {'witness': 'Allow'})
        self.assertEqual(self.case['url'], '/api/v1/secrets?watch=true&fieldSelector=metadata.name%3Dtoken')
        self.assertEqual(witness_request(validate_report(self.report, self.contract, 'violated'), self.identities), self.request)

    def test_unnamed_collection_and_named_get_round_trip_urls(self):
        self.assertEqual(request_url({**self.request, 'name': ''})['url'], '/api/v1/secrets?watch=true')
        self.assertEqual(request_url({**self.request, 'verb': 'list', 'name': ''})['url'], '/api/v1/secrets')
        named = {**self.request, 'verb': 'get', 'namespace': 'frontend'}
        self.assertEqual(request_url(named)['url'], '/api/v1/namespaces/frontend/secrets/token')
        validate_request({**self.request, 'name': ''}, self.identities)
        validate_request({**self.request, 'namespace': 'frontend', 'name': ''}, self.identities)

    def test_url_attribute_corruption_never_becomes_a_green_comparison(self):
        for key, value in [('verb', 'get'), ('namespace', 'frontend'), ('name', ''), ('resource', 'configmaps'),
                           ('apiGroup', 'apps'), ('apiVersion', 'v2'), ('subresource', 'status'),
                           ('resourceRequest', False), ('resourceRequest', 1), ('username', 'alice'),
                           ('groups', []), ('path', '/wrong')]:
            candidate = copy.deepcopy(self.url_result)
            candidate['data']['decisions'][0]['attributes'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_url_result(candidate, [self.case])

    def test_url_incomplete_or_incoherent_envelopes_rejected(self):
        for key, value in [('schema_version', True), ('kind', 'old-mode'), ('valid', False),
                           ('decisions', []), ('validation_errors', ['invalid'])]:
            candidate = copy.deepcopy(self.url_result)
            candidate['data'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_url_result(candidate, [self.case])
        for key, value in [('field_selector_error', True), ('label_selector_error', 0),
                           ('error', 'unresolved'), ('decision', 'Deny'), ('id', 'other')]:
            candidate = copy.deepcopy(self.url_result)
            candidate['data']['decisions'][0][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_url_result(candidate, [self.case])
        candidate = copy.deepcopy(self.url_result)
        candidate['data']['decisions'] *= 2
        with self.assertRaises(RuntimeError):
            validate_url_result(candidate, [self.case])

    def test_profile_domain_does_not_coerce_upstream_attributes(self):
        for change in [{'verb': 'get'}, {'verb': 'get', 'namespace': 'frontend', 'name': ''},
                       {'name': '*'}, {'name': 'Token'}, {'namespace': 'Upper'}, {'verb': 'delete'},
                       {'apiGroup': 'apps'}, {'resource': 'pods'}, {'subresource': 'status'},
                       {'resourceRequest': False}, {'groups': []}, {'name': None}, {'namespace': None}]:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                validate_request({**self.request, **change}, self.identities)

    def test_contract_null_namespace_requires_collection_verb(self):
        for change in [{'verb': 'get', 'namespace': None}, {'verb': 'delete'}, {'namespace': ''},
                       {'names': ['']}, {'names': ['*']}, {'names': []}, {'names': ['x', 'x']}]:
            candidate = copy.deepcopy(self.contract)
            candidate['clauses'][1].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                validate_contract(candidate)
        for field in ['verb', 'namespace']:
            candidate = copy.deepcopy(self.contract)
            del candidate['clauses'][1][field]
            with self.assertRaises(RuntimeError):
                validate_contract(candidate)

    def test_scope_matches_exact_endpoint_verb_and_effective_name(self):
        scope = {'subject': self.request['username'], 'namespace': None, 'resource': 'secrets',
                 'verb': 'watch', 'names': None}
        self.assertTrue(scope_matches(scope, self.request))
        self.assertTrue(scope_matches(scope, {**self.request, 'name': ''}))
        self.assertFalse(scope_matches(scope, {**self.request, 'namespace': 'payments'}))
        self.assertFalse(scope_matches(scope, {**self.request, 'verb': 'list'}))
        selected = {**scope, 'names': ['token']}
        self.assertTrue(scope_matches(selected, self.request))
        self.assertFalse(scope_matches(selected, {**self.request, 'name': ''}))

    def test_frozen_context_version_profile_and_verb_are_bound(self):
        for field, value in [('schema_version', 1), ('kind', 'other')]:
            changed = copy.deepcopy(self.report)
            changed['data']['frozen_spec'][field] = value
            with self.assertRaises(RuntimeError):
                validate_report(changed, self.contract, 'violated')
        changed = copy.deepcopy(self.report)
        changed['data']['assurance']['profile'] = 'kubernetes-rbac-v1.34-get-v1'
        with self.assertRaises(RuntimeError):
            validate_report(changed, self.contract, 'violated')
        for field, value in [('verb', 'watch'), ('namespace', None), ('names', ['settings'])]:
            changed = copy.deepcopy(self.report)
            contract = copy.deepcopy(self.contract)
            contract['clauses'][1][field] = value
            changed['data']['frozen_spec']['canonical'] = json.dumps(contract)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate_report(changed, self.contract, 'violated')

    def test_canonical_set_order_is_independent_but_clause_order_matters(self):
        reordered = copy.deepcopy(self.contract)
        reordered['context']['identities'].reverse()
        for identity in reordered['context']['identities']:
            identity['groups'].reverse()
        reordered['change_scope'].reverse()
        self.assertEqual(normalize_contract(reordered), normalize_contract(self.contract))
        reordered['clauses'].reverse()
        self.assertNotEqual(normalize_contract(reordered), normalize_contract(self.contract))


if __name__ == '__main__':
    unittest.main()
