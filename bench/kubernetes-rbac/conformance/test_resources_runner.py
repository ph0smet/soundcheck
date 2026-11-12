#!/usr/bin/env python3
"""Reject malformed or self-confirming resource-conformance evidence."""
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_resources as campaign


class ResourceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.spec = campaign.contract()
        self.report = dict(returncode=0, data=dict(schema_version=10, result='proved',
            property='kubernetes-rbac-access', assurance=dict(profile=campaign.PROFILE,
                status='within_profile', findings=[]), frozen_spec=dict(schema_version=5,
                kind='kubernetes-rbac-access', canonical=json.dumps(self.spec)),
            clause=None, counterexample=None))

    def test_pin_inventory_includes_expected_results(self):
        inputs = campaign.planned_inputs()
        pins = {key: dict(sha256=campaign.byte_hash(value), bytes=len(value)) for key, value in inputs.items()}
        campaign.audit_pins(inputs, pins)
        self.assertTrue(any(key.endswith('/expected.json') for key in inputs))
        changed = dict(inputs)
        changed['contract.json'] += b'\n'
        with self.assertRaises(RuntimeError):
            campaign.audit_pins(changed, pins)
        del pins['contract.json']
        with self.assertRaises(RuntimeError):
            campaign.audit_pins(inputs, pins)

    def test_fixed_catalogue_and_literal_expectations(self):
        self.assertEqual(len(campaign.CATALOGUE), 8)
        self.assertEqual(len(campaign.KINDS), 8)
        requests = campaign.matrix_requests()
        for row in requests:
            campaign.validate_request(row)
        self.assertEqual(len({row['id'] for row in requests}), len(requests))
        for case in campaign.matrix_cases():
            self.assertEqual(set(case['expected']), {row['id'] for row in requests})
            self.assertTrue(set(case['expected'].values()) <= {'Allow', 'NoOpinion'})
        cases = {case['id']: case for case in campaign.matrix_cases()}
        self.assertEqual(set(cases['wrong-group-pairs']['expected'].values()), {'NoOpinion'})
        self.assertEqual(set(cases['wildcard-like-literals']['expected'].values()), {'NoOpinion'})
        self.assertEqual(set(cases['star-resource-name-is-literal']['expected'].values()), {'NoOpinion'})
        for row in requests:
            if row['resource'] == 'nodes':
                self.assertEqual(cases['whole-wildcards-rolebinding-to-clusterrole']['expected'][row['id']], 'NoOpinion')

    def test_request_domain_is_strict(self):
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError):
                campaign.validate_request(row)
        row = campaign.request('', 'nodes', namespace='')
        campaign.validate_request(row)
        with self.assertRaises(RuntimeError):
            campaign.validate_request(row, version=4)
        with self.assertRaises(RuntimeError):
            campaign.validate_request(dict(row, groups=['unexpected']))
        with self.assertRaises(RuntimeError):
            campaign.validate_request(dict(row, resourceRequest=1))
        with self.assertRaises(RuntimeError):
            campaign.validate_request(dict(row, extra=True))

    def test_resource_witness_registry_is_lossless_and_not_suffix_parsing(self):
        for kind, (group, resource, namespaced) in campaign.KINDS.items():
            value = dict(counterexample=dict(principal='app', identity_groups=[], action='patch',
                object_request=dict(namespace='team-a' if namespaced else '', resource_kind=kind, name='settings'),
                granting_rules=['some grant']))
            request = campaign.witness_request(value, self.spec)
            self.assertEqual((request['apiGroup'], request['resource']), (group, resource))
        invalid = dict(counterexample=dict(principal='app', identity_groups=[], action='get',
            object_request=dict(namespace='team-a', resource_kind='deployments.apps.fake', name='settings'), granting_rules=[]))
        with self.assertRaises(RuntimeError):
            campaign.witness_request(invalid, self.spec)
        invalid['counterexample']['object_request']['resource_kind'] = 'deployments.apps'
        with self.assertRaises(RuntimeError):
            campaign.witness_request(invalid, campaign.contract(version=4))

    def test_scope_requires_exact_api_group(self):
        selected = campaign.scope(resource='deployments', group='apps')
        row = campaign.request('apps', 'deployments')
        self.assertTrue(campaign.scope_matches(selected, row))
        self.assertFalse(campaign.scope_matches(selected, dict(row, apiGroup='')))
        selected = campaign.scope(resource='nodes', namespace=None)
        self.assertTrue(campaign.scope_matches(selected, campaign.request('', 'nodes', namespace='')))
        self.assertFalse(campaign.scope_matches(selected, campaign.request('', 'nodes', namespace='team-a')))

    def test_report_envelope_and_frozen_identity(self):
        campaign.audit_report(self.report, self.spec, 'proved')
        for field, value in [('schema_version', True), ('schema_version', 10.0), ('result', 'violated'),
                             ('counterexample', {}), ('property', 'unrelated'), ('clause', {}), ('assurance', {'profile': campaign.PROFILE})]:
            altered = copy.deepcopy(self.report)
            altered['data'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                campaign.audit_report(altered, self.spec, 'proved')
        for mutate in ['exit', 'profile', 'findings', 'schema', 'group', 'scope', 'version', 'groups']:
            altered = copy.deepcopy(self.report)
            if mutate == 'exit':
                altered['returncode'] = 1
            elif mutate == 'profile':
                altered['data']['assurance']['profile'] = campaign.LEGACY_PROFILE
            elif mutate == 'findings':
                altered['data']['assurance']['findings'] = ['ignored warning']
            elif mutate == 'schema':
                altered['data']['frozen_spec']['schema_version'] = 5.0
            else:
                spec = copy.deepcopy(self.spec)
                if mutate == 'group':
                    spec['clauses'][0]['api_group'] = 'apps'
                elif mutate == 'scope':
                    spec['change_scope'] = [campaign.scope(resource='pods')]
                elif mutate == 'version':
                    spec['schema_version'] = 5.0
                else:
                    spec['context']['identities'][0]['groups'] = ['changed']
                altered['data']['frozen_spec']['canonical'] = json.dumps(spec)
            with self.subTest(mutation=mutate), self.assertRaises(RuntimeError):
                campaign.audit_report(altered, self.spec, 'proved')

    def test_native_urls_require_exact_attributes_and_decisions(self):
        expected = campaign.url_cases()
        native = dict(returncode=0, data=dict(schema_version=1, kind='rbac_request_url_authorization',
            valid=True, validation_errors=[], decisions=[dict(id=row['request']['id'],
                attributes=copy.deepcopy(row['attributes']), decision=row['decision'], error='', reason='',
                field_selector_error=False, label_selector_error=False) for row in expected]))
        campaign.audit_urls(native, expected)
        for mutation in ['missing', 'duplicate', 'id', 'namespace', 'group', 'resource', 'decision', 'bool', 'error']:
            altered = copy.deepcopy(native)
            rows = altered['data']['decisions']
            if mutation == 'missing':
                rows.pop()
            elif mutation == 'duplicate':
                rows[-1] = copy.deepcopy(rows[0])
            elif mutation == 'id':
                rows[0]['id'] = 'invented'
            elif mutation in ['namespace', 'resource']:
                rows[0]['attributes'][mutation] = 'invented'
            elif mutation == 'group':
                rows[0]['attributes']['apiGroup'] = 'invented'
            elif mutation == 'decision':
                rows[0]['decision'] = 'NoOpinion' if rows[0]['decision'] == 'Allow' else 'Allow'
            elif mutation == 'bool':
                rows[0]['attributes']['resourceRequest'] = 1
            else:
                rows[0]['error'] = 'failed'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                campaign.audit_urls(altered, expected)

    def test_preflight_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            arguments = ['--reference', str(folder/'reference'), '--model', str(folder/'model'),
                '--soundcheck', str(folder/'soundcheck'), '--module-metadata', str(folder/'module.json'),
                '--output', str(folder/'results.json')]
            with mock.patch.object(campaign, 'module_provenance', side_effect=RuntimeError('preflight stop')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(arguments), 1)
            result = campaign.read_json(folder/'results.json')
            self.assertFalse(result['complete'])
            self.assertEqual(result['failures'], ['preflight stop'])


if __name__ == '__main__':
    unittest.main()
