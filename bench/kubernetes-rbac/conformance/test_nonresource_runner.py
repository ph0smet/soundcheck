#!/usr/bin/env python3
"""Adversarial conformance-checker controls; no native oracle, solver, or cluster."""
import copy
import json
import unittest

from run import read_json
from run_nonresource import (HERE, PROFILE, audit_comparison, audit_input_pins,
    audit_model_grants, audit_report, cases, checked_decisions, encoded,
    expected_grants, planned_inputs, rejected_cases, requests_for)
from run_preparation import byte_hash, validate_transformation


class NonresourceChecks(unittest.TestCase):
    def setUp(self):
        self.contract = read_json(HERE/'contract.json')
        self.cases = {case['id']: case for case in cases()}
        self.case = self.cases['separate-cluster-binding']
        self.request = dict(id='control', username='app', groups=[], verb='get', apiGroup='',
            resource='configmaps', namespace='team-a', name='settings', resourceRequest=True, subresource='')

    def model(self, request=None, case=None):
        request, case = request or self.request, case or self.case
        grants = expected_grants(case, request)
        return dict(returncode=0, data=dict(status='supported', matrix_smt='(set-logic ALL)', decisions=[
            dict(id=request['id'], decision='Allow' if grants else 'NoOpinion', grants=grants)]))

    def violated(self):
        case = self.cases['separate-resource-wildcard']
        request = dict(self.request, id='witness', resource='secrets')
        witness = dict(principal='app', action='get', path='', host='', scheme='', sni='', headers=[],
            source_ip='0.0.0.0', route=None, service=None, shadowed_route=None, shadowed_service=None,
            object_request=dict(namespace='team-a', resource_kind='secrets', name='settings'),
            identity_groups=[], granting_rules=expected_grants(case, request))
        return case, dict(returncode=3, data=dict(result='violated', schema_version=10,
            property=self.contract['kind'], assurance=dict(profile=PROFILE, status='within_profile', findings=[]),
            frozen_spec=dict(schema_version=3, kind=self.contract['kind'], canonical=json.dumps(self.contract)),
            clause=dict(name='secrets-not-granted', kind='must_not_grant', description='Secret access is forbidden.'),
            counterexample=witness))

    def test_planned_pins_cover_every_case_and_fixed_contract(self):
        inputs = planned_inputs()
        self.assertEqual(len(inputs), len(cases())+len(rejected_cases())+2)
        audit_input_pins(inputs, read_json(HERE/'inputs.json'))
        pins = read_json(HERE/'inputs.json')
        for transform in [lambda p: p.pop('contract.json'),
                          lambda p: p['contract.json'].update(sha256='0'*64),
                          lambda p: p['contract.json'].update(bytes=True),
                          lambda p: p.update(invented={'sha256':'0'*64, 'bytes':0})]:
            changed = copy.deepcopy(pins)
            transform(changed)
            with self.assertRaises(RuntimeError):
                audit_input_pins(inputs, changed)

    def test_matrix_contains_allowed_and_denied_users_namespaces_names_and_verbs(self):
        requests = requests_for(self.contract)
        self.assertEqual({r['verb'] for r in requests}, {'get', 'list', 'watch', 'update', 'patch', 'delete'})
        self.assertEqual({r['namespace'] for r in requests}, {'team-a', 'team-b', 'unseen', ''})
        self.assertEqual({r['name'] for r in requests}, {'settings', 'other', ''})
        self.assertEqual({r['resource'] for r in requests}, {'configmaps', 'secrets'})
        self.assertEqual(len({r['username'] for r in requests}), 4)
        self.assertEqual(len({r['id'] for r in requests}), len(requests))
        for case in self.cases.values():
            decisions_ = {bool(expected_grants(case, r)) for r in requests}
            self.assertEqual(decisions_, {False} if case['mode'] == 'none' else {False, True})

    def test_original_rule_indices_and_binding_namespace_are_asserted(self):
        self.assertEqual(expected_grants(self.case, self.request),
            ['ClusterRoleBinding/coexistence -> ClusterRole/coexistence/rules/1'])
        patch = dict(self.request, verb='patch')
        self.assertEqual(expected_grants(self.case, patch),
            ['ClusterRoleBinding/coexistence -> ClusterRole/coexistence/rules/3'])
        rb = self.cases['separate-role-binding']
        self.assertEqual(expected_grants(rb, dict(self.request, namespace='team-b')), [])
        self.assertEqual(expected_grants(rb, dict(self.request, verb='list', namespace='', name='')), [])
        audit_model_grants(self.model(), [self.request], self.case)
        for label in ['ClusterRoleBinding/coexistence -> ClusterRole/coexistence/rules/0',
                      'ClusterRoleBinding/coexistence -> ClusterRole/coexistence/rules/2', 'invented']:
            model = self.model()
            model['data']['decisions'][0]['grants'] = [label]
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                audit_model_grants(model, [self.request], self.case)

    def test_empty_null_url_fields_cannot_disable_wildcard_resource_grants(self):
        for name in ['wildcard-empty-cluster', 'wildcard-null-cluster', 'wildcard-absent-cluster',
                     'wildcard-empty-role', 'wildcard-null-role']:
            case = self.cases[name]
            request = dict(self.request, verb='delete', resource='secrets', name='other')
            self.assertTrue(expected_grants(case, request), name)
            model = self.model(request, case)
            model['data']['decisions'][0].update(decision='NoOpinion', grants=[])
            with self.subTest(case=name), self.assertRaises(RuntimeError):
                audit_model_grants(model, [request], case)

    def test_decision_protocol_cannot_hide_rows_fields_errors_or_support_changes(self):
        mutations = [lambda d: d.update(extra=True), lambda d: d.pop('matrix_smt'),
            lambda d: d.update(decisions=[]), lambda d: d['decisions'].append(d['decisions'][0]),
            lambda d: d['decisions'][0].update(id='wrong'), lambda d: d['decisions'][0].update(extra=True),
            lambda d: d['decisions'][0].update(grants=[]), lambda d: d.update(status='unknown')]
        for mutation in mutations:
            value = self.model()
            mutation(value['data'])
            with self.assertRaises(RuntimeError):
                checked_decisions(value, [self.request], 'model')
        native = dict(returncode=0, data=dict(valid=True, validation_errors=[], decisions=[
            dict(id='control', decision='Allow', reason='native grant', error='')]))
        checked_decisions(native, [self.request], 'reference')
        for mutation in [lambda d: d.update(valid=1), lambda d: d.update(validation_errors=['error']),
                         lambda d: d['decisions'][0].update(error='resolution failed'),
                         lambda d: d['decisions'][0].update(extra='invented')]:
            value = copy.deepcopy(native)
            mutation(value['data'])
            with self.assertRaises(RuntimeError):
                checked_decisions(value, [self.request], 'reference')

    def test_unknown_cannot_be_counted_as_a_successful_decision(self):
        model = dict(returncode=0, data=dict(status='unknown', decisions=[], reason='resourceRequest must be true'))
        self.assertIsNone(checked_decisions(model, [self.request], 'model', allow_unsupported=True))
        with self.assertRaises(RuntimeError):
            checked_decisions(model, [self.request], 'model')
        for mutation in [lambda d: d.update(reason=''), lambda d: d.update(matrix_smt='invented'),
                         lambda d: d.update(decisions=self.model()['data']['decisions'])]:
            value = copy.deepcopy(model)
            mutation(value['data'])
            with self.assertRaises(RuntimeError):
                checked_decisions(value, [self.request], 'model', allow_unsupported=True)

    def test_report_binds_exact_contract_clause_scope_and_trace(self):
        case, value = self.violated()
        request = audit_report(value, self.contract, 'violated', case)
        self.assertEqual(request['resource'], 'secrets')
        mutations = [lambda d: d.update(schema_version=True), lambda d: d.update(extra=True),
            lambda d: d.update(property='rbac-repair-preservation'),
            lambda d: d['assurance'].update(profile='kubernetes-rbac-v1.34-read-write-v1'),
            lambda d: d['clause'].update(name='required-config'),
            lambda d: d['clause'].update(kind='must_allow'),
            lambda d: d['clause'].update(description=''),
            lambda d: d['counterexample']['object_request'].update(namespace='team-b'),
            lambda d: d['counterexample']['object_request'].update(resource_kind='configmaps'),
            lambda d: d['counterexample'].update(identity_groups=['invented']),
            lambda d: d['counterexample'].update(action='patch'),
            lambda d: d['counterexample'].update(granting_rules=['ClusterRoleBinding/coexistence -> ClusterRole/coexistence/rules/0']),
            lambda d: d['counterexample'].update(path='/healthz')]
        for mutation in mutations:
            changed = copy.deepcopy(value)
            mutation(changed['data'])
            with self.assertRaises(RuntimeError):
                audit_report(changed, self.contract, 'violated', case)
        changed = copy.deepcopy(value)
        contract = copy.deepcopy(self.contract)
        contract['clauses'][1]['namespace'] = 'other'
        changed['data']['frozen_spec']['canonical'] = json.dumps(contract)
        with self.assertRaises(RuntimeError):
            audit_report(changed, self.contract, 'violated', case)

    def test_url_content_loss_cannot_pass_preparation_audit(self):
        original = encoded(self.case['snapshot'])
        validate_transformation(original, original, [])
        for mutation in ['alter', 'drop', 'reorder']:
            changed = copy.deepcopy(self.case['snapshot'])
            if mutation == 'alter':
                changed['items'][0]['rules'][0]['nonResourceURLs'] = ['/readyz']
            elif mutation == 'drop':
                del changed['items'][0]['rules'][0]
            else:
                changed['items'][0]['rules'].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                validate_transformation(original, encoded(changed), [])

    def test_proved_and_unknown_reports_cannot_hide_witnesses_or_wrong_assurance(self):
        _, value = self.violated()
        value['returncode'] = 0
        value['data'].update(result='proved', clause=None, counterexample=None)
        audit_report(value, self.contract, 'proved')
        preserved = copy.deepcopy(value)
        preserved['data']['property'] = 'rbac-repair-preservation'
        audit_report(preserved, self.contract, 'proved', preservation=True)
        with self.assertRaises(RuntimeError):
            audit_report(value, self.contract, 'proved', preservation=True)
        unknown = copy.deepcopy(value)
        unknown['returncode'] = 4
        unknown['data'].update(result='unknown', reason='mixed rule')
        unknown['data']['assurance'].update(status='unsupported', findings=[dict(
            code='unsupported-rbac-input', service=None, route=None, detail='mixed rule')])
        audit_report(unknown, self.contract, 'unknown')
        for mutation in [lambda d: d.update(reason=''), lambda d: d.pop('reason'),
                         lambda d: d['assurance'].update(status='within_profile'),
                         lambda d: d['assurance'].update(findings=[]),
                         lambda d: d.update(counterexample={}), lambda d: d.update(clause={})]:
            changed = copy.deepcopy(unknown)
            mutation(changed['data'])
            with self.assertRaises(RuntimeError):
                audit_report(changed, self.contract, 'unknown')

    def test_typed_policy_difference_requires_real_hashes_object_identity_and_inequality(self):
        original, changed = b'original', b'changed'
        value = dict(returncode=1, data=dict(schema_version=1, kind='typed_rbac_policy_comparison', valid=True,
            original_sha256=byte_hash(original), prepared_sha256=byte_hash(changed), policy_equal=False,
            original_policy_sha256='a'*64, prepared_policy_sha256='b'*64, original_objects=2, prepared_objects=2,
            validation_errors=[], differences=['changed: ClusterRole\x00\x00coexistence']))
        audit_comparison(value, original, changed, False, 2)
        for mutation in [lambda d: d.update(policy_equal=True), lambda d: d.update(differences=[]),
                         lambda d: d.update(differences=['changed: invented']),
                         lambda d: d.update(prepared_policy_sha256='a'*64),
                         lambda d: d.update(prepared_objects=1), lambda d: d.update(valid=1)]:
            corrupted = copy.deepcopy(value)
            mutation(corrupted['data'])
            with self.assertRaises(RuntimeError):
                audit_comparison(corrupted, original, changed, False, 2)


if __name__ == '__main__':
    unittest.main()
