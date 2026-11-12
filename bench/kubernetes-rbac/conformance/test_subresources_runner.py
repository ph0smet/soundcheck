#!/usr/bin/env python3
"""Negative evidence-consumer tests, independent of production verification."""
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_subresources as campaign


class SubresourceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.spec = campaign.contract()
        self.proof = dict(returncode=0, data=dict(schema_version=10, result='proved', property='kubernetes-rbac-access',
            assurance=dict(profile=campaign.PROFILE, status='within_profile', findings=[]),
            frozen_spec=dict(schema_version=7, kind='kubernetes-rbac-access', canonical=json.dumps(self.spec)),
            clause=None, counterexample=None))

    def test_frozen_inventory_and_literal_expectations(self):
        inputs = campaign.planned_inputs()
        campaign.audit_pins(inputs, campaign.read_json(campaign.HERE/'inputs.json'))
        self.assertEqual(len(inputs), 210)
        self.assertEqual(len(campaign.CATALOGUE), 8)
        self.assertEqual(sum(len(e[4]) for e in campaign.CATALOGUE), 19)
        self.assertEqual(len(campaign.matrix_requests()), 460)
        self.assertEqual(len(campaign.matrix_cases()), 30)
        self.assertEqual(len(campaign.contract_cases()), 39)
        self.assertEqual(len(campaign.url_cases()), 96)
        self.assertEqual(campaign.planned_counts(), dict(matrix_comparisons=13800, url_comparisons=480,
            contract_native_checks=22800, rejected_requests=102, legacy_rejected_requests=140,
            contract_witness_replays=5, preservation_witness_replays=8))
        self.assertTrue(any(b'{broken' in v for k, v in inputs.items() if k.endswith('/requests.json')))
        for mutation in ['changed-expected', 'missing', 'extra']:
            altered = dict(inputs)
            if mutation == 'changed-expected':
                altered['matrix/empty-policy/expected.json'] += b' '
            elif mutation == 'missing':
                altered.pop('catalogue.json')
            else:
                altered['new'] = b'{}'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_pins(altered, campaign.read_json(campaign.HERE/'inputs.json'))

    def test_matrix_is_within_exact_operation_domains(self):
        for row in campaign.matrix_requests():
            campaign.validate_request(row)
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError):
                campaign.validate_request(row)
        for row in campaign.matrix_requests():
            if row['subresource']:
                with self.subTest(id=row['id']), self.assertRaises(RuntimeError):
                    campaign.validate_request(row, version=6)
        named = campaign.request('', 'pods', 'exec', 'create')
        campaign.validate_request(named)
        for mutation in [dict(name=''), dict(namespace=''), dict(apiGroup='apps'), dict(verb='update'),
                         dict(groups=['unexpected']), dict(username='unknown'), dict(resourceRequest=1), dict(extra=True)]:
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.validate_request(dict(named, **mutation))
        for version in [True, 7.0, 8]:
            with self.assertRaises(RuntimeError):
                campaign.validate_request(named, version=version)
        campaign.validate_request(campaign.request('', 'pods', verb='create', name=''))
        with self.assertRaises(RuntimeError):
            campaign.validate_request(campaign.request('', 'pods', verb='create', name='settings'))

    def test_base_scope_never_matches_subresource(self):
        request = campaign.request('', 'pods', 'exec', 'create')
        self.assertFalse(campaign.scope_matches(campaign.scope(resource='pods', verb='create'), request))
        self.assertFalse(campaign.scope_matches(campaign.scope(resource='pods', subresource='exec', verb='get'), request))
        self.assertTrue(campaign.scope_matches(campaign.scope(resource='pods', subresource='exec', verb='create'), request))
        self.assertFalse(campaign.scope_matches(campaign.scope(resource='pods', subresource='exec', verb='create', names={'exclude': ['settings'], 'include_empty': False}), request))

    def test_report_rejects_downgrades_and_rewritten_contract(self):
        campaign.audit_report(self.proof, self.spec, 'proved')
        for field, value in [('schema_version', True), ('schema_version', 10.0), ('result', 'unknown'),
                             ('property', 'other'), ('clause', {}), ('counterexample', {})]:
            changed = copy.deepcopy(self.proof)
            changed['data'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.spec, 'proved')
        for mutation in ['exit', 'bool-exit', 'profile', 'findings', 'frozen-version', 'subresource', 'group', 'verb', 'name', 'identity', 'scope']:
            changed = copy.deepcopy(self.proof)
            data = changed['data']
            if mutation == 'exit': changed['returncode'] = 3
            elif mutation == 'bool-exit': changed['returncode'] = False
            elif mutation == 'profile': data['assurance']['profile'] = campaign.LEGACY_PROFILE
            elif mutation == 'findings': data['assurance']['findings'] = ['ignored']
            elif mutation == 'frozen-version': data['frozen_spec']['schema_version'] = 7.0
            else:
                altered = copy.deepcopy(self.spec)
                if mutation == 'subresource': altered['clauses'][0]['subresource'] = ''
                elif mutation == 'group': altered['clauses'][0]['api_group'] = 'apps'
                elif mutation == 'verb': altered['clauses'][0]['verb'] = 'create'
                elif mutation == 'name': altered['clauses'][0]['names'] = None
                elif mutation == 'identity': altered['context']['identities'][1]['groups'] = []
                else: altered['change_scope'] = []
                data['frozen_spec']['canonical'] = json.dumps(altered)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.spec, 'proved')
        altered = copy.deepcopy(self.proof)
        altered['data']['frozen_spec']['canonical'] = '{"schema_version":7,"schema_version":7}'
        with self.assertRaises(RuntimeError): campaign.audit_report(altered, self.spec, 'proved')

    def test_witness_is_named_and_belongs_to_the_failed_clause(self):
        case = next(c for c in campaign.contract_cases() if c['id'] == 'unsafe-exec')
        report = dict(clause=dict(name='forbidden-exec', kind='must_not_grant'), counterexample=dict(principal='app',
            identity_groups=[], action='create', granting_rules=['exec'], object_request=dict(namespace='team-a', resource_kind='pods/exec', name='settings')))
        campaign.audit_witness(report, case)
        for field, value in [('name', ''), ('namespace', ''), ('resource_kind', 'pods'), ('resource_kind', 'pods/attach')]:
            altered = copy.deepcopy(report)
            altered['counterexample']['object_request'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError): campaign.audit_witness(altered, case)
        for field, value in [('action', 'get'), ('principal', 'ops'), ('identity_groups', ['operators']), ('granting_rules', ['x', 'x'])]:
            altered = copy.deepcopy(report)
            altered['counterexample'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError): campaign.audit_witness(altered, case)
        altered = copy.deepcopy(report)
        altered['clause']['kind'] = 'must_allow'
        with self.assertRaises(RuntimeError): campaign.audit_witness(altered, case)

    def test_preservation_uses_full_context_and_exact_change_coordinates(self):
        case = next(c for c in campaign.contract_cases() if c['id'] == 'v7-unmentioned-deployments-scale')
        report = dict(clause=dict(name='preservation-outside-change-scope', kind='must_preserve'), counterexample=dict(principal='ops',
            identity_groups=['operators'], action='update', granting_rules=[], object_request=dict(namespace='team-b', resource_kind='deployments/scale.apps', name='settings')))
        campaign.audit_witness(report, case, True)
        for field, value in [('resource_kind', 'deployments.apps'), ('resource_kind', 'deployments/scale'), ('namespace', '')]:
            altered = copy.deepcopy(report)
            altered['counterexample']['object_request'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError): campaign.audit_witness(altered, case, True)
        altered = copy.deepcopy(case)
        altered['contract']['change_scope'] = [campaign.scope(group='apps', resource='deployments', subresource='scale', verb='update', namespace='team-b', subject='ops')]
        with self.assertRaises(RuntimeError): campaign.audit_witness(report, altered, True)
        altered['contract']['change_scope'][0]['subresource'] = ''
        campaign.audit_witness(report, altered, True)
        altered['contract']['schema_version'] = 6
        with self.assertRaises(RuntimeError): campaign.audit_witness(report, altered, True)

    def test_url_evidence_rejects_attribute_or_decision_corruption(self):
        expected = campaign.url_expected(['settings'])
        execution = dict(returncode=0, data=dict(schema_version=1, kind='rbac_request_url_authorization', valid=True,
            validation_errors=[], decisions=[dict(id=r['request']['id'], attributes=copy.deepcopy(r['attributes']), decision=r['decision'],
                reason='', error='', field_selector_error=False, label_selector_error=False) for r in expected]))
        campaign.audit_urls(execution, expected)
        for bad_exit in [False, 0.0, 1]:
            altered = dict(execution, returncode=bad_exit)
            with self.subTest(exit=bad_exit), self.assertRaises(RuntimeError): campaign.audit_urls(altered, expected)
        for mutation in ['missing', 'duplicate', 'unexpected', 'subresource', 'name', 'namespace', 'group', 'verb', 'bool', 'decision', 'error', 'field', 'label']:
            altered = copy.deepcopy(execution)
            rows = altered['data']['decisions']
            if mutation == 'missing': rows.pop()
            elif mutation == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
            elif mutation == 'unexpected': rows[0]['id'] = 'unknown'
            elif mutation in ['subresource', 'name', 'namespace']: rows[0]['attributes'][mutation] = 'wrong'
            elif mutation == 'group': rows[0]['attributes']['apiGroup'] = 'apps'
            elif mutation == 'verb': rows[0]['attributes']['verb'] = 'watch'
            elif mutation == 'bool': rows[0]['attributes']['resourceRequest'] = 1
            elif mutation == 'decision': rows[0]['decision'] = 'NoOpinion'
            elif mutation == 'error': rows[0]['error'] = 'problem'
            elif mutation == 'field': rows[0]['field_selector_error'] = True
            else: rows[0]['label_selector_error'] = True
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_urls(altered, expected)
        fabricated = next(r for r in campaign.url_expected(None) if r['request']['id'] == 'fabricated-pods-scale')
        self.assertEqual(fabricated['decision'], 'Allow')
        self.assertFalse(fabricated['supported'])

    def test_unknown_is_not_noopinion_and_bad_smt_cannot_pass(self):
        row = campaign.request('', 'pods', 'exec')
        unknown = dict(returncode=0, data=dict(status='unknown', reason='outside domain', decisions=[]))
        self.assertIsNone(campaign.decisions(unknown, [row], 'model', allow_unsupported=True))
        with self.assertRaises(RuntimeError): campaign.decisions(unknown, [row], 'model')
        for mutation in [dict(reason=''), dict(decisions=[dict(id='request', decision='NoOpinion', grants=[])]), dict(status='supported')]:
            altered = dict(unknown, data=dict(unknown['data'], **mutation))
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.decisions(altered, [row], 'model', allow_unsupported=True)
        from run import smt_result
        for output in ['false false', 'true unknown', 'true false true false', 'unknown']:
            with self.subTest(output=output), self.assertRaises(RuntimeError): smt_result(dict(returncode=0, stdout=output, stderr=''), [row])
        native = dict(returncode=0, data=dict(valid=True, validation_errors=[], decisions=[dict(id='request', decision='NoOpinion', error='', reason='')]))
        self.assertEqual(campaign.decisions(native, [row], 'reference'), {'request': 'NoOpinion'})
        for field, value in [('decision', 'Deny'), ('decision', 'Unknown'), ('error', 'lookup failed')]:
            altered = copy.deepcopy(native)
            altered['data']['decisions'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError): campaign.decisions(altered, [row], 'reference')

    def test_source_pin_inventory_and_content_fail_closed(self):
        pins = campaign.read_json(campaign.HERE/'source-pins.json')
        self.assertEqual(set(pins), set(campaign.SOURCE_FILES))
        for module, entries in pins.items(): self.assertEqual(set(entries), set(campaign.SOURCE_FILES[module]))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kube, api = root/'kubernetes@v1.34.0', root/'apiserver@v0.34.0'
            metadata = root/'modules.json'
            campaign.save(metadata, dict(Dir=str(kube)))
            artificial = {}
            for module, names in campaign.SOURCE_FILES.items():
                base = kube if module == 'kubernetes' else api
                artificial[module] = {}
                for name in names:
                    path = base/name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(module+'/'+name)
                    artificial[module][name] = campaign.digest(path)
            real_read = campaign.read_json
            def read(path): return copy.deepcopy(artificial) if path == campaign.HERE/'source-pins.json' else real_read(path)
            with mock.patch.object(campaign, 'read_json', side_effect=read):
                self.assertEqual(len(campaign.source_provenance(metadata)), 18)
                victim = kube/campaign.SOURCE_FILES['kubernetes'][0]
                victim.write_text('altered')
                with self.assertRaises(RuntimeError): campaign.source_provenance(metadata)
                artificial['kubernetes'].pop(campaign.SOURCE_FILES['kubernetes'][0])
                with self.assertRaises(RuntimeError): campaign.source_provenance(metadata)

    def test_completion_requires_exact_counters_and_case_inventory(self):
        result = dict(native_only=False, failures=[], inputs_unchanged=True, binaries_unchanged=True, cases={}, **campaign.planned_counts())
        for case in campaign.matrix_cases(): result['cases']['matrix/'+case['id']] = dict(matrix_comparisons=460)
        for case in campaign.contract_cases():
            entry = dict(native_contract=case['expected'], native_comparison=case['comparison'], contract=case['expected'])
            if case['baseline'] is not None: entry['comparison'] = case['comparison']
            result['cases']['contracts/'+case['id']] = entry
        campaign.audit_completion(result)
        for field in campaign.planned_counts():
            for value in [0, result[field]-1, result[field]+1, float(result[field]), True]:
                altered = copy.deepcopy(result)
                altered[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(RuntimeError): campaign.audit_completion(altered)
        for mutation in ['case-missing', 'case-changed', 'case-extra', 'mode', 'source', 'binary', 'failures']:
            altered = copy.deepcopy(result)
            if mutation == 'case-missing': altered['cases'].pop('matrix/empty-policy')
            elif mutation == 'case-changed': altered['cases']['matrix/empty-policy']['matrix_comparisons'] = 459
            elif mutation == 'case-extra': altered['cases']['extra'] = {}
            elif mutation == 'mode': altered['native_only'] = True
            elif mutation == 'source': altered['inputs_unchanged'] = False
            elif mutation == 'binary': altered['binaries_unchanged'] = 1
            else: altered['failures'] = ['failure']
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_completion(altered)

    def test_failed_preflight_retains_incomplete_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            argv = ['--native-only', '--reference', str(root/'ref'), '--module-metadata', str(root/'modules.json'), '--output', str(root/'results.json')]
            with mock.patch.object(campaign, 'module_provenance', side_effect=RuntimeError('preflight failed')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(argv), 1)
            report = campaign.read_json(root/'results.json')
            self.assertFalse(report['complete'])
            self.assertEqual(report['failures'], ['preflight failed'])
            self.assertFalse((root/'before-execution.json').exists())


if __name__ == '__main__':
    unittest.main()
