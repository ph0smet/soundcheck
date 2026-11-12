#!/usr/bin/env python3
"""Fail-closed checks for the aggregation campaign's evidence consumers."""
import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_aggregation as campaign


class AggregationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.case = campaign.cases()[0]
        self.source = campaign.encoded(self.case['snapshot'])
        self.expected = campaign.encoded(self.case['expected_rules'])
        seeded = copy.deepcopy(self.case['snapshot'])
        for item in seeded['items']:
            if item.get('aggregationRule') is not None:
                item['rules'] = [campaign.rule('sentinel', None, group='soundcheck-reference.invalid')]
        self.controller = dict(returncode=0, data=dict(schema_version=1,
            kind='upstream_aggregation_controller_reference', source_sha256=campaign.byte_hash(self.source),
            expected_sha256=campaign.byte_hash(self.expected), valid=True, validation_errors=[],
            controller_executed=True, expected_reached=True, aggregate_roles=['root'],
            reconciliations=['root'], updates=[dict(name='root', resource_version='1', rules=[campaign.rule()])], seeded_snapshot=seeded,
            snapshot=copy.deepcopy(self.case['snapshot'])))
        self.contract = campaign.contract()
        self.report = dict(returncode=0, data=dict(schema_version=10, result='proved',
            property='kubernetes-rbac-access', assurance=dict(profile=campaign.PROFILE,
                status='within_profile', findings=[]), frozen_spec=dict(schema_version=3,
                kind='kubernetes-rbac-access', canonical=json.dumps(self.contract)),
            clause=None, counterexample=None))

    def audit(self, value):
        return campaign.audit_controller(value, self.case, self.source, self.expected)

    def test_entrypoint_module_metadata_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            metadata, output = folder/'module.json', folder/'results.json'
            called = []

            def metadata_reader(path):
                self.assertEqual(path, metadata)
                called.append(path)
                raise RuntimeError('deliberate preflight stop')

            arguments = ['--reference', str(folder/'reference'), '--model', str(folder/'model'),
                '--soundcheck', str(folder/'soundcheck'), '--module-metadata', str(metadata),
                '--output', str(output)]
            with mock.patch.object(campaign, 'module_provenance', metadata_reader), \
                    mock.patch.object(campaign.shutil, 'which', return_value='/test/z3'), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(arguments), 1)
            self.assertEqual(called, [metadata])
            self.assertEqual(campaign.read_json(output)['failures'], ['deliberate preflight stop'])

    def test_valid_controller_evidence(self):
        self.assertEqual(self.audit(self.controller), self.case['snapshot'])

    def test_missing_native_execution_cannot_pass(self):
        for field, value in [('schema_version', True), ('kind', 'pretend-controller'),
            ('valid', False), ('controller_executed', False), ('expected_reached', False),
            ('validation_errors', ['failed']), ('source_sha256', 'bad'), ('expected_sha256', 'bad'),
            ('aggregate_roles', []), ('aggregate_roles', ['root', 'missing']), ('updates', []), ('reconciliations', []),
            ('updates', [dict(name='root', resource_version='0', rules=[campaign.rule()])]),
            ('updates', [dict(name='missing', rules=[])])]:
            with self.subTest(field=field, value=value):
                value = copy.deepcopy(value)
                changed = copy.deepcopy(self.controller)
                changed['data'][field] = value
                with self.assertRaises(RuntimeError):
                    self.audit(changed)
        changed = copy.deepcopy(self.controller)
        changed['returncode'] = 1
        with self.assertRaises(RuntimeError):
            self.audit(changed)

    def test_seed_cannot_replace_original_policy(self):
        changed = copy.deepcopy(self.controller)
        changed['data']['seeded_snapshot'] = copy.deepcopy(self.case['snapshot'])
        with self.assertRaises(RuntimeError):
            self.audit(changed)
        changed = copy.deepcopy(self.controller)
        changed['data']['seeded_snapshot']['items'][0]['rules'] = []
        with self.assertRaises(RuntimeError):
            self.audit(changed)

    def test_controller_output_cannot_define_expectations(self):
        for mutation in ['drop-rule', 'change-url', 'change-label', 'drop-object', 'change-subject', 'change-selector']:
            changed = copy.deepcopy(self.controller)
            items = changed['data']['snapshot']['items']
            if mutation == 'drop-rule':
                items[1]['rules'] = []
            elif mutation == 'change-url':
                items[1]['rules'].append(dict(verbs=['get'], nonResourceURLs=['/healthz']))
            elif mutation == 'change-label':
                items[0]['metadata']['labels']['selected'] = 'no'
            elif mutation == 'drop-object':
                items.pop(0)
            elif mutation == 'change-subject':
                items[-1]['subjects'][0]['name'] = 'someone-else'
            else:
                items[1]['aggregationRule']['clusterRoleSelectors'] = [{}]
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.audit(changed)

    def test_exact_pin_inventory(self):
        inputs = campaign.planned_inputs()
        pins = {key: dict(sha256=campaign.byte_hash(value), bytes=len(value)) for key, value in inputs.items()}
        campaign.audit_pins(inputs, pins)
        changed = dict(inputs)
        changed['match-labels.json'] += b'\n'
        with self.assertRaises(RuntimeError):
            campaign.audit_pins(changed, pins)
        del pins['match-labels.json']
        with self.assertRaises(RuntimeError):
            campaign.audit_pins(inputs, pins)

    def test_report_protocol_and_frozen_requirements(self):
        self.assertIsNone(campaign.audit_report(self.report, self.contract, 'proved'))
        for change in ['old-profile', 'missing-profile', 'schema', 'returncode', 'weakened-contract', 'wrong-property']:
            changed = copy.deepcopy(self.report)
            if change == 'old-profile':
                changed['data']['assurance']['profile'] = 'kubernetes-rbac-v1.34-read-write-v2'
            elif change == 'missing-profile':
                del changed['data']['assurance']['profile']
            elif change == 'schema':
                changed['data']['schema_version'] = True
            elif change == 'returncode':
                changed['returncode'] = 4
            elif change == 'weakened-contract':
                weakened = copy.deepcopy(self.contract)
                weakened['clauses'][1]['names'] = ['only-this-secret']
                changed['data']['frozen_spec']['canonical'] = json.dumps(weakened)
            else:
                changed['data']['property'] = 'rbac-repair-preservation'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.contract, 'proved')

    def test_empty_or_duplicate_decision_rows_fail(self):
        requests = campaign.requests_for(self.contract)[:2]
        rows = [dict(id=r['id'], decision='Allow', reason='test', error='') for r in requests]
        execution = dict(returncode=0, data=dict(valid=True, validation_errors=[], decisions=rows))
        self.assertEqual(len(campaign.checked_decisions(execution, requests, 'reference')), 2)
        for rows in [[], [rows[0], rows[0]], [dict(rows[0], error='unresolved'), rows[1]]]:
            changed = copy.deepcopy(execution)
            changed['data']['decisions'] = rows
            with self.assertRaises(RuntimeError):
                campaign.checked_decisions(changed, requests, 'reference')

    def test_preservation_clause_and_native_replay_coordinates(self):
        report = copy.deepcopy(self.report)
        report['returncode'] = 3
        report['data'].update(result='violated', property='rbac-repair-preservation',
            clause=dict(name='preservation-outside-change-scope', kind='must_preserve',
                description='"operator" get core configmaps "status" in namespace "ops" changed from Allow to NoOpinion outside the approved change scope'),
            counterexample=dict(principal='operator', action='get', path='', host='', scheme='', sni='',
                headers=[], source_ip='0.0.0.0', route=None, service=None, shadowed_route=None,
                shadowed_service=None, object_request=dict(namespace='ops', resource_kind='configmaps', name='status'),
                identity_groups=[], granting_rules=[]))
        self.assertEqual(campaign.audit_report(report, self.contract, 'violated', preservation=True)['username'], 'operator')
        for mutation in ['null-clause', 'wrong-kind', 'wrong-name', 'wrong-description', 'wrong-identity', 'wrong-groups', 'wrong-name-coordinate']:
            changed = copy.deepcopy(report)
            if mutation == 'null-clause':
                changed['data']['clause'] = None
            elif mutation == 'wrong-kind':
                changed['data']['clause']['kind'] = 'must_allow'
            elif mutation == 'wrong-name':
                changed['data']['clause']['name'] = 'other'
            elif mutation == 'wrong-description':
                changed['data']['clause']['description'] = 'NoOpinion to Allow'
            elif mutation == 'wrong-identity':
                changed['data']['counterexample']['principal'] = 'app'
                changed['data']['counterexample']['identity_groups'] = ['readers']
            elif mutation == 'wrong-groups':
                changed['data']['counterexample']['identity_groups'] = ['admin']
            else:
                changed['data']['counterexample']['object_request']['name'] = 'other'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_report(changed, self.contract, 'violated', preservation=True)


if __name__ == '__main__':
    unittest.main()
