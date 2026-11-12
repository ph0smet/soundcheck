#!/usr/bin/env python3
"""Fail closed on malformed collection-write campaign evidence."""
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_collection_writes as campaign


class CollectionWriteEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.spec = campaign.contract()
        self.proof = dict(returncode=0, data=dict(schema_version=10, result='proved', property='kubernetes-rbac-access',
            assurance=dict(profile=campaign.PROFILE, status='within_profile', findings=[]),
            frozen_spec=dict(schema_version=6, kind='kubernetes-rbac-access', canonical=json.dumps(self.spec)),
            clause=None, counterexample=None))

    def test_frozen_inputs_cover_expectations_and_bodies(self):
        inputs = campaign.planned_inputs()
        pins = campaign.read_json(campaign.HERE/'inputs.json')
        campaign.audit_pins(inputs, pins)
        self.assertEqual(len(inputs), 119)
        self.assertTrue(any(b'generateName' in value for key, value in inputs.items() if key.endswith('/requests.json')))
        self.assertTrue(any(key.endswith('/expected.json') for key in inputs))
        for mutation in ['bytes', 'missing', 'extra']:
            changed = dict(inputs)
            if mutation == 'bytes':
                changed['contract.json'] += b'\n'
            elif mutation == 'missing':
                del changed['contract.json']
            else:
                changed['unreviewed.json'] = b'{}'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_pins(changed, pins)

    def test_literals_include_empty_names_and_preserve_legacy_domain(self):
        requests = campaign.matrix_requests()
        self.assertEqual(len(requests), 320)
        cases = {case['id']: case for case in campaign.matrix_cases()}
        self.assertEqual(len(cases), 20)
        for row in requests:
            campaign.validate_request(row)
            if row['verb'] in campaign.NEW_VERBS:
                self.assertEqual(row['name'], '')
                with self.assertRaises(RuntimeError):
                    campaign.validate_request(row, version=5)
                self.assertEqual(cases['named-resourceNames']['expected'][row['id']], 'NoOpinion')
                self.assertEqual(cases['literal-star-resourceNames']['expected'][row['id']], 'NoOpinion')
                self.assertEqual(cases['empty-resourceNames']['expected'][row['id']], 'Allow' if row['username'] == 'app' else 'NoOpinion')
                if row['resource'] == 'nodes':
                    self.assertEqual(cases['role-binding-cluster-role']['expected'][row['id']], 'NoOpinion')
            else:
                campaign.validate_request(row, version=5)
        for case in cases.values():
            self.assertEqual(set(case['expected']), {row['id'] for row in requests})
        self.assertEqual(set(cases['wrong-group-and-subresource']['expected'].values()), {'NoOpinion'})

    def test_domain_rejects_named_or_all_namespace_collection_writes(self):
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError):
                campaign.validate_request(row)
        valid = campaign.request('', 'nodes', verb='create', namespace='', name='')
        campaign.validate_request(valid)
        for edit in [dict(groups=['new']), dict(resourceRequest=1), dict(extra=True), dict(namespace='team-a'),
                     dict(name='settings'), dict(apiGroup='apps')]:
            with self.subTest(edit=edit), self.assertRaises(RuntimeError):
                campaign.validate_request(dict(valid, **edit))
        for version in [True, 6.0, 7]:
            with self.assertRaises(RuntimeError):
                campaign.validate_request(valid, version=version)

    def test_report_rejects_profile_or_requirement_downgrades(self):
        campaign.audit_report(self.proof, self.spec, 'proved')
        for field, value in [('schema_version', True), ('schema_version', 10.0), ('result', 'violated'),
                             ('property', 'other'), ('clause', {}), ('counterexample', {})]:
            changed = copy.deepcopy(self.proof)
            changed['data'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.spec, 'proved')
        for mutation in ['exit', 'profile', 'findings', 'frozen-version', 'canonical-version', 'verb', 'empty-name', 'groups', 'scope']:
            changed = copy.deepcopy(self.proof)
            data = changed['data']
            if mutation == 'exit':
                changed['returncode'] = 3
            elif mutation == 'profile':
                data['assurance']['profile'] = campaign.LEGACY_PROFILE
            elif mutation == 'findings':
                data['assurance']['findings'] = ['ignored']
            elif mutation == 'frozen-version':
                data['frozen_spec']['schema_version'] = 6.0
            else:
                spec = copy.deepcopy(self.spec)
                if mutation == 'canonical-version':
                    spec['schema_version'] = 6.0
                elif mutation == 'verb':
                    spec['clauses'][0]['verb'] = 'get'
                elif mutation == 'empty-name':
                    spec['clauses'][0]['names'] = ['settings']
                elif mutation == 'groups':
                    spec['context']['identities'][0]['groups'] = ['new']
                else:
                    spec['change_scope'] = []
                data['frozen_spec']['canonical'] = json.dumps(spec)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.spec, 'proved')

    def test_witness_requires_supported_empty_name_and_actual_clause(self):
        case = next(c for c in campaign.contract_cases() if c['id'] == 'unsafe-bulk-delete')
        report = dict(clause=dict(name='forbidden-bulk-delete', kind='must_not_grant'),
            counterexample=dict(principal='app', identity_groups=[], action='deletecollection', granting_rules=['grant'],
                object_request=dict(namespace='team-a', resource_kind='pods', name='')))
        campaign.audit_witness(report, case)
        for field, value in [('name', 'settings'), ('namespace', ''), ('resource_kind', 'pods.example')]:
            changed = copy.deepcopy(report)
            changed['counterexample']['object_request'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                campaign.audit_witness(changed, case)
        for field, value in [('action', 'delete'), ('principal', 'ops'), ('identity_groups', ['new']), ('granting_rules', ['x', 'x'])]:
            changed = copy.deepcopy(report)
            changed['counterexample'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                campaign.audit_witness(changed, case)
        changed = copy.deepcopy(report)
        changed['clause']['kind'] = 'must_allow'
        with self.assertRaises(RuntimeError):
            campaign.audit_witness(changed, case)

    def test_preservation_witness_cannot_hide_inside_approved_changes(self):
        case = next(c for c in campaign.contract_cases() if c['id'] == 'v6-unmentioned-create')
        report = dict(clause=dict(name='preservation-outside-change-scope', kind='must_preserve'),
            counterexample=dict(principal='ops', identity_groups=['operators'], action='create', granting_rules=[],
                object_request=dict(namespace='', resource_kind='nodes', name='')))
        campaign.audit_witness(report, case, True)
        changed = copy.deepcopy(case)
        changed['contract']['change_scope'] = [campaign.scope(resource='nodes', verb='create', namespace=None, names=None, subject='ops')]
        with self.assertRaises(RuntimeError):
            campaign.audit_witness(report, changed, True)
        for field, value in [('action', 'deletecollection'), ('principal', 'app')]:
            wrong = copy.deepcopy(report)
            wrong['counterexample'][field] = value
            if field == 'principal':
                wrong['counterexample']['identity_groups'] = []
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                campaign.audit_witness(wrong, case, True)
        changed = copy.deepcopy(case)
        changed['contract']['schema_version'] = 5
        with self.assertRaises(RuntimeError):
            campaign.audit_witness(report, changed, True)

    def test_url_evidence_requires_exact_name_namespace_and_selector_flags(self):
        expected = campaign.url_expected([''])
        value = dict(returncode=0, data=dict(schema_version=1, kind='rbac_request_url_authorization', valid=True,
            validation_errors=[], decisions=[dict(id=row['request']['id'], attributes=copy.deepcopy(row['attributes']),
                decision=row['decision'], error='', reason='', field_selector_error=row['field_selector_error'],
                label_selector_error=row['label_selector_error']) for row in expected]))
        campaign.audit_urls(value, expected)
        for mutation in ['missing', 'duplicate', 'name', 'namespace', 'group', 'bool', 'decision', 'field-error', 'label-error', 'error']:
            changed = copy.deepcopy(value)
            rows = changed['data']['decisions']
            if mutation == 'missing':
                rows.pop()
            elif mutation == 'duplicate':
                rows[-1] = copy.deepcopy(rows[0])
            elif mutation in ['name', 'namespace']:
                rows[0]['attributes'][mutation] = 'wrong'
            elif mutation == 'group':
                rows[0]['attributes']['apiGroup'] = 'wrong'
            elif mutation == 'bool':
                rows[0]['attributes']['resourceRequest'] = 1
            elif mutation == 'decision':
                rows[0]['decision'] = 'NoOpinion'
            elif mutation == 'field-error':
                rows[0]['field_selector_error'] = True
            elif mutation == 'label-error':
                rows[0]['label_selector_error'] = True
            else:
                rows[0]['error'] = 'failed'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_urls(changed, expected)

    def test_failed_preflight_never_reports_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            argv = ['--reference', str(folder/'reference'), '--model', str(folder/'model'), '--soundcheck', str(folder/'soundcheck'),
                    '--module-metadata', str(folder/'modules.json'), '--output', str(folder/'results.json')]
            with mock.patch.object(campaign, 'module_provenance', side_effect=RuntimeError('preflight stop')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(argv), 1)
            result = campaign.read_json(folder/'results.json')
            self.assertFalse(result['complete'])
            self.assertEqual(result['failures'], ['preflight stop'])


if __name__ == '__main__':
    unittest.main()
