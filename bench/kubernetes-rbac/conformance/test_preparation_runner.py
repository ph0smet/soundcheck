#!/usr/bin/env python3
"""Preparation protocol/receipt guards, without Go, Z3 or a cluster."""
import copy
import json
import unittest

from run import PROFILE
from run_preparation import (byte_hash, validate_policy_comparison,
                             validate_receipt, validate_transformation)


def encoded(value):
    return (json.dumps(value) + '\n').encode()


class PreparationChecks(unittest.TestCase):
    def setUp(self):
        self.source = {'apiVersion': 'v1', 'kind': 'List', 'metadata': {'resourceVersion': '12'},
                       'items': [{'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role',
                                  'metadata': {'name': 'reader', 'namespace': 'demo', 'uid': 'fixed',
                                               'annotations': {'review': 'keep exact'}},
                                  'rules': [{'verbs': ['get'], 'apiGroups': [''], 'resources': ['configmaps']}]}]}
        self.target = copy.deepcopy(self.source)
        del self.target['metadata']['resourceVersion']
        del self.target['items'][0]['metadata']['uid']
        self.original, self.prepared = encoded(self.source), encoded(self.target)
        self.removed = ['manifest.items[0].metadata.uid', 'manifest.metadata.resourceVersion']
        self.receipt = {
            'schema_version': 1, 'kind': 'rbac-snapshot-preparation', 'target_profile': PROFILE,
            'input': {'sha256': byte_hash(self.original), 'bytes': len(self.original)},
            'snapshot': {'sha256': byte_hash(self.prepared), 'bytes': len(self.prepared)},
            'object_count': 1, 'removed_fields': self.removed,
            'verification_performed': False, 'completeness_established': False}
        self.comparison = {'returncode': 0, 'data': {
            'schema_version': 1, 'kind': 'typed_rbac_policy_comparison', 'valid': True,
            'original_sha256': byte_hash(self.original), 'prepared_sha256': byte_hash(self.prepared),
            'policy_equal': True, 'original_policy_sha256': 'a'*64, 'prepared_policy_sha256': 'a'*64,
            'original_objects': 1, 'prepared_objects': 1, 'validation_errors': [], 'differences': []}}

    def test_matching_receipt_and_policy_projection(self):
        validate_receipt(self.receipt, self.original, self.prepared, self.removed)
        validate_policy_comparison(self.comparison, self.original, self.prepared)

    def test_receipt_cannot_claim_verification_or_completeness(self):
        for key in ['verification_performed', 'completeness_established']:
            for value in [True, None, 0]:
                changed = copy.deepcopy(self.receipt)
                changed[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    validate_receipt(changed, self.original, self.prepared, self.removed)

    def test_receipt_binds_exact_bytes_and_schema(self):
        for key, value in [('schema_version', True), ('kind', 'verification'),
                           ('target_profile', 'other'), ('object_count', True),
                           ('object_count', 0), ('removed_fields', []),
                           ('removed_fields', self.removed + self.removed)]:
            changed = copy.deepcopy(self.receipt)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                validate_receipt(changed, self.original, self.prepared, self.removed)
        for side in ['input', 'snapshot']:
            for key, value in [('sha256', 'f'*64), ('bytes', 0), ('bytes', True)]:
                changed = copy.deepcopy(self.receipt)
                changed[side][key] = value
                with self.subTest(side=side, key=key), self.assertRaises(RuntimeError):
                    validate_receipt(changed, self.original, self.prepared, self.removed)
        changed = copy.deepcopy(self.receipt)
        changed['unreviewed'] = 'extra'
        with self.assertRaises(RuntimeError):
            validate_receipt(changed, self.original, self.prepared, self.removed)

    def test_only_fixed_metadata_removals_are_permitted(self):
        changed = copy.deepcopy(self.target)
        changed['items'][0]['rules'][0]['verbs'] = ['*']
        with self.assertRaises(RuntimeError):
            validate_transformation(self.original, encoded(changed), self.removed)
        changed = copy.deepcopy(self.target)
        changed['items'] = []
        with self.assertRaises(RuntimeError):
            validate_transformation(self.original, encoded(changed), self.removed)
        changed = copy.deepcopy(self.target)
        del changed['items'][0]['metadata']['annotations']
        with self.assertRaises(RuntimeError):
            validate_transformation(self.original, encoded(changed), self.removed)
        for paths in [list(reversed(self.removed)), self.removed + self.removed,
                      ['manifest.items[0].metadata.name'], ['manifest.items[9].metadata.uid'],
                      ['manifest.items[-1].metadata.uid'], ['manifest.items[0].rules'],
                      ['manifest/metadata/resourceVersion'], ['manifest.items[0].metadata.unknown']]:
            with self.subTest(paths=paths), self.assertRaises(RuntimeError):
                validate_transformation(self.original, self.prepared, paths)

    def test_normalization_cannot_silently_remove_empty_containers_or_rewrite_literals(self):
        changed = copy.deepcopy(self.target)
        del changed['metadata']
        with self.assertRaises(RuntimeError):
            validate_transformation(self.original, encoded(changed), self.removed)
        changed = copy.deepcopy(self.target)
        changed['items'][0]['metadata']['annotations']['review'] = 'changed'
        with self.assertRaises(RuntimeError):
            validate_transformation(self.original, encoded(changed), self.removed)
        for output in [self.prepared.rstrip(b'\n'), self.prepared+b'\n', self.prepared+b'{}']:
            with self.subTest(output=output), self.assertRaises((RuntimeError, ValueError)):
                validate_transformation(self.original, output, self.removed)

    def test_duplicate_original_keys_cannot_be_laundered(self):
        duplicate = self.original.replace(b'"kind": "List"', b'"kind": "List", "kind": "List"')
        with self.assertRaises(RuntimeError):
            validate_transformation(duplicate, self.prepared, self.removed)

    def test_policy_comparison_cannot_invent_validity_or_equality(self):
        for key, value in [('valid', False), ('valid', 1), ('schema_version', True),
                           ('kind', 'other'), ('policy_equal', False), ('policy_equal', 1),
                           ('original_sha256', '0'*64), ('prepared_sha256', '0'*64),
                           ('original_policy_sha256', None), ('prepared_policy_sha256', 'b'*64),
                           ('original_objects', True), ('prepared_objects', 0),
                           ('validation_errors', ['original invalid']), ('differences', ['removed'])]:
            changed = copy.deepcopy(self.comparison)
            changed['data'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                validate_policy_comparison(changed, self.original, self.prepared)
        changed = copy.deepcopy(self.comparison)
        changed['returncode'] = 1
        with self.assertRaises(RuntimeError):
            validate_policy_comparison(changed, self.original, self.prepared)
        changed = copy.deepcopy(self.comparison)
        del changed['data']['policy_equal']
        with self.assertRaises(RuntimeError):
            validate_policy_comparison(changed, self.original, self.prepared)

    def test_corrupted_policy_control_requires_a_real_difference(self):
        changed = copy.deepcopy(self.comparison)
        changed['returncode'] = 1
        changed['data'].update(policy_equal=False, prepared_policy_sha256='b'*64,
                               differences=['changed: Role/demo/reader'])
        validate_policy_comparison(changed, self.original, self.prepared, equal=False)
        for key, value in [('differences', []), ('prepared_policy_sha256', 'a'*64), ('policy_equal', True)]:
            bad = copy.deepcopy(changed)
            bad['data'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_policy_comparison(bad, self.original, self.prepared, equal=False)


if __name__ == '__main__':
    unittest.main()
