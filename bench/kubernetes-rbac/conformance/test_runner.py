#!/usr/bin/env python3
"""Negative acceptance checks: broken adapters must not produce a green run."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from run import (decisions, fixture_path, scope_matches, smt_result, strict_json,
                 validate_contract, validate_report, validate_requests, witness_request)


class ProtocolChecks(unittest.TestCase):
    def setUp(self):
        self.identities = {'alice': ['team']}
        self.contract = {
            'schema_version': 1, 'kind': 'kubernetes-rbac-access',
            'context': {'schema_version': 1, 'snapshot_complete': True,
                        'identities': [{'username': 'alice', 'groups': ['team']}]},
            'clauses': [{'name': 'keep-config', 'kind': 'must_allow', 'subject': 'alice',
                         'namespace': 'frontend', 'resource': 'configmaps', 'names': None},
                        {'name': 'no-secrets', 'kind': 'must_not_grant', 'subject': 'alice',
                         'namespace': 'payments', 'resource': 'secrets', 'names': None}],
            'change_scope': [{'subject': 'alice', 'namespace': 'payments', 'resource': 'secrets', 'names': None}]}
        self.request = {'id': 'first', 'username': 'alice', 'groups': ['team'], 'verb': 'get',
                        'apiGroup': '', 'resourceRequest': True, 'subresource': '', 'namespace': 'frontend',
                        'resource': 'configmaps', 'name': 'settings'}
        self.requests = [self.request, {**self.request, 'id': 'second', 'name': 'other'}]
        self.reference = {'returncode': 0, 'data': {'valid': True, 'validation_errors': [], 'decisions': [
            {'id': 'first', 'decision': 'Allow', 'reason': 'RBAC grant', 'error': ''},
            {'id': 'second', 'decision': 'NoOpinion', 'reason': '', 'error': ''}]}}
        self.model = {'returncode': 0, 'data': {'status': 'supported', 'decisions': [
            {'id': 'first', 'decision': 'Allow', 'grants': ['RoleBinding/frontend/config']},
            {'id': 'second', 'decision': 'NoOpinion', 'grants': []}]}}
        self.report = {'returncode': 0, 'data': {
            'schema_version': 10, 'result': 'proved', 'counterexample': None,
            'assurance': {'profile': 'kubernetes-rbac-v1.34-get-v1', 'status': 'within_profile'},
            'frozen_spec': {'schema_version': 1, 'kind': 'kubernetes-rbac-access',
                            'canonical': json.dumps(self.contract)}}}

    def test_complete_responses(self):
        self.assertEqual(decisions(self.reference, self.requests, 'reference'),
                         decisions(self.model, self.requests, 'model'))
        self.assertEqual(validate_contract(self.contract), self.identities)
        validate_requests(self.requests, self.identities)
        validate_report(self.report, self.contract, 'proved')

    def test_missing_null_duplicate_wrong_decisions_cannot_skip_comparison(self):
        candidates = []
        for rows in [[], None, self.reference['data']['decisions'][:1], self.reference['data']['decisions'] * 2]:
            value = copy.deepcopy(self.reference)
            value['data']['decisions'] = rows
            candidates.append(value)
        for key, value in [('id', 'first'), ('id', 'unexpected'), ('id', None),
                           ('decision', None), ('decision', 'Deny'), ('error', 'unresolved'), ('reason', None)]:
            candidate = copy.deepcopy(self.reference)
            candidate['data']['decisions'][1][key] = value
            candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                decisions(candidate, self.requests, 'reference')

    def test_invalid_validation_or_exit_status_rejected(self):
        for key, value in [('valid', 1), ('valid', False), ('validation_errors', None),
                           ('validation_errors', ['invalid input'])]:
            candidate = copy.deepcopy(self.reference)
            candidate['data'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                decisions(candidate, self.requests, 'reference')
        candidate = copy.deepcopy(self.reference)
        candidate['returncode'] = 1
        with self.assertRaises(RuntimeError):
            decisions(candidate, self.requests, 'reference')

    def test_invalid_input_is_not_a_successful_replay(self):
        invalid = {'returncode': 1, 'data': {'valid': False, 'validation_errors': ['invalid'], 'decisions': []}}
        self.assertIsNone(decisions(invalid, self.requests, 'reference', allow_unsupported=True))
        with self.assertRaises(RuntimeError):
            decisions(invalid, self.requests, 'reference')
        invalid['returncode'] = 0
        with self.assertRaises(RuntimeError):
            decisions(invalid, self.requests, 'reference', allow_unsupported=True)

    def test_unknown_model_requires_reason_and_empty_decisions(self):
        unknown = {'returncode': 0, 'data': {'status': 'unknown', 'reason': 'aggregation', 'decisions': []}}
        self.assertIsNone(decisions(unknown, self.requests, 'model', allow_unsupported=True))
        with self.assertRaises(RuntimeError):
            decisions(unknown, self.requests, 'model')
        for key, value in [('reason', ''), ('reason', None), ('decisions', self.model['data']['decisions'])]:
            candidate = copy.deepcopy(unknown)
            candidate['data'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                decisions(candidate, self.requests, 'model', allow_unsupported=True)

    def test_grant_labels_must_agree_with_model_decision(self):
        for index, grants in [(0, []), (0, None), (0, ['x', 'x']), (0, [None]), (1, ['x'])]:
            candidate = copy.deepcopy(self.model)
            candidate['data']['decisions'][index]['grants'] = grants
            with self.subTest(index=index, grants=grants), self.assertRaises(RuntimeError):
                decisions(candidate, self.requests, 'model')

    def test_smt_results_require_in_domain_ground_booleans(self):
        self.assertEqual(smt_result({'returncode': 0, 'stdout': 'true\ntrue\ntrue\nfalse\n'}, self.requests),
                         {'first': 'Allow', 'second': 'NoOpinion'})
        for text in ['', 'true true', 'true true true false true false',
                     'false true true false', 'true unknown true false',
                     '(error "bad formula")', 'true (not false) true false']:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                smt_result({'returncode': 0, 'stdout': text}, self.requests)
        with self.assertRaises(RuntimeError):
            smt_result({'returncode': 1, 'stdout': 'true true true false'}, self.requests)
        with self.assertRaises(RuntimeError):
            smt_result({'returncode': 0, 'stdout': 'true true true false', 'stderr': 'bad formula'}, self.requests)

    def test_wrong_profile_cannot_claim_reference_agreement(self):
        candidate = copy.deepcopy(self.report)
        candidate['data']['assurance']['profile'] = 'another-profile'
        with self.assertRaises(RuntimeError):
            validate_report(candidate, self.contract, 'proved')

    def test_frozen_contract_must_not_be_substituted(self):
        for key, value in [('result', 'violated'), ('schema_version', 9), ('counterexample', {})]:
            candidate = copy.deepcopy(self.report)
            candidate['data'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_report(candidate, self.contract, 'proved')
        candidate = copy.deepcopy(self.report)
        changed = copy.deepcopy(self.contract)
        changed['clauses'] = changed['clauses'][:1]
        candidate['data']['frozen_spec']['canonical'] = json.dumps(changed)
        with self.assertRaises(RuntimeError):
            validate_report(candidate, self.contract, 'proved')
        candidate = copy.deepcopy(self.report)
        candidate['returncode'] = 3
        with self.assertRaises(RuntimeError):
            validate_report(candidate, self.contract, 'proved')
        candidate = copy.deepcopy(self.report)
        candidate['data']['frozen_spec']['schema_version'] = True
        with self.assertRaises(RuntimeError):
            validate_report(candidate, self.contract, 'proved')

    def test_canonical_set_order_is_irrelevant_but_clause_order_is_frozen(self):
        contract = copy.deepcopy(self.contract)
        contract['context']['identities'][0]['groups'] = ['team', 'another']
        contract['context']['identities'].append({'username': 'zebra', 'groups': []})
        contract['clauses'][0]['names'] = ['z', 'a']
        contract['change_scope'].append(copy.deepcopy(contract['change_scope'][0]))
        canonical = copy.deepcopy(contract)
        canonical['context']['identities'].reverse()
        canonical['context']['identities'][1]['groups'].reverse()
        canonical['clauses'][0]['names'].reverse()
        canonical['change_scope'] = canonical['change_scope'][:1]
        report = copy.deepcopy(self.report)
        report['data']['frozen_spec']['canonical'] = json.dumps(canonical)
        validate_report(report, contract, 'proved')
        canonical['clauses'].reverse()
        report['data']['frozen_spec']['canonical'] = json.dumps(canonical)
        with self.assertRaises(RuntimeError):
            validate_report(report, contract, 'proved')

    def test_complete_snapshot_and_fixed_identity_context_are_required(self):
        for key, value in [('snapshot_complete', False), ('snapshot_complete', 1), ('schema_version', True)]:
            candidate = copy.deepcopy(self.contract)
            candidate['context'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                validate_contract(candidate)
        candidate = copy.deepcopy(self.contract)
        candidate['context']['identities'].append(candidate['context']['identities'][0])
        with self.assertRaises(RuntimeError):
            validate_contract(candidate)

    def test_request_scope_and_identity_cannot_change(self):
        for key, value in [('username', 'other'), ('groups', []), ('verb', 'list'), ('apiGroup', 'apps'),
                           ('resourceRequest', 1), ('subresource', 'status'), ('resource', 'pods'),
                           ('namespace', 'a' * 64), ('name', 'x\x00suffix'), ('name', 'a' * 254)]:
            candidate = {**self.request, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                validate_requests([candidate], self.identities)
        # Kubernetes' DNS-subdomain validator has a total 253-byte limit,
        # without a separate 63-byte limit on each label.
        validate_requests([{**self.request, 'name': 'a' * 253}], self.identities)
        with self.assertRaises(RuntimeError):
            validate_requests([self.request, self.request], self.identities)

    def test_witness_keeps_frozen_groups_and_scope(self):
        report = {'counterexample': {'principal': 'alice', 'identity_groups': ['team'], 'action': 'get',
                                    'object_request': {'namespace': 'frontend', 'resource_kind': 'configmaps', 'name': 'x'},
                                    'granting_rules': []}}
        request = witness_request(report, self.identities)
        self.assertTrue(scope_matches(self.contract['clauses'][0], request))
        self.assertFalse(any(scope_matches(s, request) for s in self.contract['change_scope']))
        report['counterexample']['identity_groups'] = ['system:authenticated']
        with self.assertRaises(RuntimeError):
            witness_request(report, self.identities)

    def test_duplicate_and_trailing_json_rejected(self):
        for source in ['{"a":1,"a":2}', '{} {}', '{"x":NaN}', '{"x":Infinity}']:
            with self.subTest(source=source), self.assertRaises((RuntimeError, ValueError)):
                strict_json(source)

    def test_case_resolution_does_not_guess_or_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder/'one.json').write_text('{}')
            self.assertEqual(fixture_path(folder, 'one'), folder/'one.json')
            (folder/'one.yaml').write_text('{}')
            for name in ['one', '../one', 'missing']:
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    fixture_path(folder, name)


if __name__ == '__main__':
    unittest.main()
