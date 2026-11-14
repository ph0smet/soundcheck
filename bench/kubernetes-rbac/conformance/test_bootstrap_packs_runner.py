#!/usr/bin/env python3
"""Adversarial checks for the bootstrap selection evidence consumer."""
import copy
import unittest

from run import PROFILE, read_json
from run_inventory import encoded, identity
from run_bootstrap_packs import PACKS, audit_completion, audit_receipt


def sample():
    source = (PACKS/'kubernetes-v1.34.0.json').read_bytes()
    catalogue = read_json(PACKS/'kubernetes-v1.34.0.json')
    row = next(p for p in catalogue['packs'] if p['name'] == 'view')
    document = dict(apiVersion='v1', kind='List', items=row['objects'])
    original = encoded(document)
    output = original
    native = dict(documents=[document], snapshot=document)
    normalization = dict(schema_version=2, kind='rbac-snapshot-preparation', target_profile=PROFILE,
        input=identity(original), snapshot=identity(output), object_count=2, removed_fields=[],
        verification_performed=False, completeness_established=False, input_format='json',
        document_count=1, selection='all', namespace_context=None, empty_documents=[],
        list_wrappers=[dict(path='documents[0]', apiVersion='v1', kind='List', item_count=2)],
        retained_objects=[dict(source_path=f'documents[0].items[{i}]', snapshot_index=i) for i in range(2)],
        excluded_objects=[], defaulted_fields=[])
    receipt = dict(schema_version=1, kind='rbac-bootstrap-selection', kubernetes_version='1.34.0',
        requested_packs=['view'], selected_packs=['view'], reference=identity(source),
        upstream=catalogue['upstream'], configuration=catalogue['configuration'],
        source_catalogue=catalogue['source_catalogue'],
        objects=[dict(identity='ClusterRole/view', pack='view', selection='requested'),
                 dict(identity='ClusterRole/system:aggregate-to-view', pack='view', selection='aggregation-dependency')],
        normalization=normalization, snapshot=identity(output), object_count=2,
        verification_performed=False, installed_state_observed=False, identity_authentication_established=False,
        completeness_established=False, limitations=['explicit boundary']*5)
    return receipt, source, ['view'], output, original, native


class BootstrapReceiptTests(unittest.TestCase):
    def test_valid_receipt(self):
        audit_receipt(*sample())

    def test_refuses_claims_or_missing_boundaries(self):
        for flag in ['verification_performed', 'installed_state_observed', 'identity_authentication_established',
                     'completeness_established']:
            args = sample()
            args[0][flag] = True
            with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                audit_receipt(*args)
        args = sample()
        del args[0]['limitations']
        with self.assertRaises(RuntimeError):
            audit_receipt(*args)

    def test_exact_source_and_output_hashes(self):
        for key in ['reference', 'snapshot']:
            args = sample()
            args[0][key]['sha256'] = '0'*64
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                audit_receipt(*args)

    def test_no_bool_integer_alias(self):
        for key in ['schema_version', 'object_count']:
            args = sample()
            args[0][key] = True
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                audit_receipt(*args)
        args = sample()
        args[0]['reference']['bytes'] = True
        with self.assertRaises(RuntimeError):
            audit_receipt(*args)

    def test_selection_and_dependency_accounting(self):
        for change in ['pack', 'dependency', 'kind', 'count']:
            args = sample()
            if change == 'pack':
                args[0]['selected_packs'] = ['cluster-admin']
            elif change == 'dependency':
                args[0]['objects'][1]['selection'] = 'requested'
            elif change == 'kind':
                args[0]['objects'][0]['identity'] = 'ClusterRoleBinding/view'
            else:
                args[0]['object_count'] = 1
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                audit_receipt(*args)

    def test_untrusted_version_or_feature_gate(self):
        args = sample()
        args[0]['kubernetes_version'] = '1.35.0'
        with self.assertRaises(RuntimeError):
            audit_receipt(*args)
        args = sample()
        args[0]['configuration'] = dict(args[0]['configuration'], DynamicResourceAllocation=False)
        with self.assertRaises(RuntimeError):
            audit_receipt(*args)

    def test_no_unaccounted_normalization(self):
        args = sample()
        args[0]['normalization']['removed_fields'] = ['documents[0].items[0].rules']
        with self.assertRaises(RuntimeError):
            audit_receipt(*args)

    def test_counter_completeness(self):
        valid = dict(failures=[], selections=15, typed_policy_comparisons=15, receipt_audits=15,
                     native_generation_equal=True, installed_state_observed=False, verification_performed=False)
        audit_completion(valid)
        for key in ['selections', 'typed_policy_comparisons', 'receipt_audits']:
            value = copy.deepcopy(valid)
            value[key] = 14
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                audit_completion(value)


if __name__ == '__main__':
    unittest.main()
