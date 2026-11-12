#!/usr/bin/env python3
"""Adversarial evidence-consumer checks; no verifier or solver is invoked."""
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_apply as campaign


def native_execution(rows, choices):
    entries = []
    for row, stages in zip(rows, choices):
        is_apply = row['operation'] in campaign.NEW_OPERATIONS
        allowed = all(s == 'Allow' for s in stages)
        status = (201 if row['operation'] == 'apply-missing' else 200) if allowed else 403
        entries.append(dict(id=row['id'], decision='Allow' if allowed else 'NoOpinion', reason='', error='',
            stages=[dict(attributes=campaign.expected_attributes(row, ('patch' if i == 0 else 'create') if is_apply else row['operation'], is_apply),
                         decision=s, reason='', error='') for i, s in enumerate(stages)],
            http_status=status if is_apply else 0, handler_entered=is_apply and stages[0] == 'Allow',
            storage_reads=int(is_apply and stages[0] == 'Allow')))
    return dict(returncode=0, data=dict(schema_version=1, kind='rbac_apply_authorization', valid=True, validation_errors=[], decisions=entries))


class ApplyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.spec = campaign.contract()
        self.proof = dict(returncode=0, data=dict(schema_version=10, result='proved', property='kubernetes-rbac-access',
            assurance=dict(profile=campaign.PROFILE, status='within_profile', findings=[]),
            frozen_spec=dict(schema_version=8, kind='kubernetes-rbac-access', canonical=json.dumps(self.spec)), clause=None, counterexample=None))

    def test_exact_frozen_inventory_and_domains(self):
        inputs = campaign.planned_inputs()
        campaign.audit_pins(inputs, campaign.read_json(campaign.HERE/'inputs.json'))
        rows = campaign.matrix_requests()
        self.assertEqual(len(rows), 1650)
        self.assertEqual(len(campaign.matrix_cases()), 29)
        self.assertEqual(len(campaign.contract_cases()), 39)
        classes = {(r['apiGroup'], r['resource'], r['subresource'], r['operation']) for r in rows}
        self.assertEqual(len(classes), 99)
        for key in classes:
            users = {r['username'] for r in rows if (r['apiGroup'], r['resource'], r['subresource'], r['operation']) == key}
            self.assertEqual(users, set(campaign.IDENTITIES))
        for row in rows: campaign.validate_request(row)
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError): campaign.validate_request(row)
        for mutation in ['changed', 'missing', 'extra']:
            altered = dict(inputs)
            if mutation == 'changed': altered['matrix/empty-policy/expected.json'] += b' '
            elif mutation == 'missing': altered.pop('catalogue.json')
            else: altered['extra'] = b'{}'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_pins(altered, campaign.read_json(campaign.HERE/'inputs.json'))

    def test_operation_and_legacy_boundaries(self):
        row = campaign.request()
        campaign.validate_request(row)
        for mutation in [dict(operation='apply'), dict(subresource='status'), dict(name=''), dict(namespace=''),
                         dict(apiGroup='apps'), dict(resourceRequest=1), dict(groups=['other']), dict(extra=True)]:
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.validate_request(dict(row, **mutation))
        with self.assertRaises(RuntimeError): campaign.validate_request(row, version=7)
        for version in [True, 8.0, 9]:
            with self.assertRaises(RuntimeError): campaign.validate_request(row, version=version)
        campaign.validate_request(campaign.request(operation='create', name=''))
        campaign.validate_request(campaign.request(resource='nodes', namespace=''))
        campaign.validate_request(campaign.request(operation='list', namespace='', name=''))
        for op in ['patch', 'apply-existing', 'apply-missing']:
            self.assertEqual(campaign.scope_matches(campaign.scope(operation=op), row), op == 'apply-missing')
        self.assertFalse(campaign.scope_matches(campaign.scope(operation='apply-missing', names={'exclude': ['settings'], 'include_empty': False}), row))

    def test_native_stage_and_control_corruption_fails(self):
        row = campaign.request()
        execution = native_execution([row], [['Allow', 'Allow']])
        self.assertEqual(campaign.audit_native(execution, [row]), {'request': 'Allow'})
        for field, value in [('returncode', False), ('returncode', 0.0), ('returncode', 1)]:
            with self.assertRaises(RuntimeError): campaign.audit_native(dict(execution, **{field: value}), [row])
        for mutation in ['missing', 'extra', 'duplicate', 'id', 'status', 'reads', 'bool-reads', 'entered', 'bool-status',
            'decision', 'error', 'stage-error', 'name', 'group', 'namespace', 'resource', 'subresource', 'version', 'username', 'groups', 'path', 'verb', 'resource-bool', 'stage-count', 'missing-field']:
            changed = copy.deepcopy(execution)
            entries = changed['data']['decisions']
            entry = entries[0]
            attrs = entry['stages'][1]['attributes']
            if mutation == 'missing': entries.clear()
            elif mutation in ['extra', 'duplicate']: entries.append(copy.deepcopy(entry))
            elif mutation == 'id': entry['id'] = 'unexpected'
            elif mutation == 'status': entry['http_status'] = 200
            elif mutation == 'reads': entry['storage_reads'] = 0
            elif mutation == 'bool-reads': entry['storage_reads'] = True
            elif mutation == 'bool-status': entry['http_status'] = 201.0
            elif mutation == 'entered': entry['handler_entered'] = 1
            elif mutation == 'decision': entry['decision'] = 'NoOpinion'
            elif mutation == 'error': entry['error'] = 'error'
            elif mutation == 'stage-error': entry['stages'][1]['error'] = 'error'
            elif mutation == 'stage-count': entry['stages'].pop()
            elif mutation == 'missing-field': del entry['stages'][1]['reason']
            elif mutation == 'group': attrs['apiGroup'] = 'apps'
            elif mutation == 'version': attrs['apiVersion'] = 'v2'
            elif mutation == 'groups': attrs['groups'] = ['invented']
            elif mutation == 'resource-bool': attrs['resourceRequest'] = 1
            else: attrs[mutation] = 'wrong'
            with self.subTest(mutation=mutation), self.assertRaises((RuntimeError, KeyError)): campaign.audit_native(changed, [row])
        # Initial denial must short-circuit; independent prerequisite diagnostics
        # are not allowed to fabricate an executed create-stage reference trace.
        denied = native_execution([row], [['NoOpinion']])
        campaign.audit_native(denied, [row])
        fabricated = native_execution([row], [['NoOpinion', 'Allow']])
        with self.assertRaises(RuntimeError): campaign.audit_native(fabricated, [row])
        existing = campaign.request(operation='apply-existing')
        campaign.audit_native(native_execution([existing], [['Allow']]), [existing])
        with self.assertRaises(RuntimeError): campaign.audit_native(native_execution([existing], [['Allow', 'Allow']]), [existing])

    def test_frozen_stage_expectations_are_enforced(self):
        row = campaign.request()
        execution = native_execution([row], [['Allow', 'NoOpinion']])
        expected = {'request': dict(decision='NoOpinion', stages=['Allow', 'NoOpinion'])}
        campaign.audit_native(execution, [row], expected)
        for changed in [dict(decision='Allow', stages=['Allow', 'Allow']), dict(decision='NoOpinion', stages=['NoOpinion'])]:
            with self.assertRaises(RuntimeError): campaign.audit_native(execution, [row], {'request': changed})

    def test_report_rejects_rewritten_operation_and_schema(self):
        campaign.audit_report(self.proof, self.spec, 'proved')
        for mutation in ['exit', 'profile', 'schema', 'contract-schema', 'operation', 'subresource', 'namespace', 'identity', 'change-scope', 'unknown']:
            altered = copy.deepcopy(self.proof)
            if mutation == 'exit': altered['returncode'] = False
            elif mutation == 'profile': altered['data']['assurance']['profile'] = campaign.legacy.PROFILE
            elif mutation == 'schema': altered['data']['schema_version'] = 10.0
            elif mutation == 'contract-schema': altered['data']['frozen_spec']['schema_version'] = 7
            elif mutation == 'unknown': altered['data']['result'] = 'unknown'
            else:
                fixed = copy.deepcopy(self.spec)
                if mutation == 'operation': fixed['clauses'][0]['operation'] = 'patch'
                elif mutation == 'subresource': fixed['clauses'][0]['subresource'] = 'status'
                elif mutation == 'namespace': fixed['clauses'][0]['namespace'] = 'other'
                elif mutation == 'identity': fixed['context']['identities'][0]['groups'] = ['extra']
                else: fixed['change_scope'] = []
                altered['data']['frozen_spec']['canonical'] = json.dumps(fixed)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_report(altered, self.spec, 'proved')

    def test_witness_operation_scopes_and_preservation(self):
        case = next(c for c in campaign.contract_cases() if c['id'] == 'unsafe-apply-create')
        report = dict(clause=dict(name='forbidden-apply-missing', kind='must_not_grant'), counterexample=dict(principal='app',
            identity_groups=[], action='apply-missing', granting_rules=['patch: x', 'create: y'], object_request=dict(namespace='team-a', resource_kind='configmaps', name='settings')))
        campaign.audit_witness(report, case)
        for field, value in [('action', 'patch'), ('action', 'apply-existing'), ('principal', 'ops'), ('identity_groups', ['operators']), ('granting_rules', ['x', 'x'])]:
            changed = copy.deepcopy(report); changed['counterexample'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError): campaign.audit_witness(changed, case)
        case = next(c for c in campaign.contract_cases() if c['id'] == 'v8-unmentioned-apply-missing')
        report = dict(clause=dict(name='preservation-outside-change-scope', kind='must_preserve'), counterexample=dict(principal='ops',
            identity_groups=['operators'], action='apply-missing', granting_rules=[], object_request=dict(namespace='team-b', resource_kind='pods', name='settings')))
        campaign.audit_witness(report, case, True)
        changed = copy.deepcopy(case)
        changed['contract']['change_scope'] = [campaign.scope(resource='pods', operation='apply-missing', namespace='team-b', subject='ops')]
        with self.assertRaises(RuntimeError): campaign.audit_witness(report, changed, True)
        changed['contract']['change_scope'][0]['operation'] = 'patch'
        campaign.audit_witness(report, changed, True)

    def test_compound_grant_evidence_keeps_both_stages(self):
        report = dict(counterexample=dict(principal='app', identity_groups=[], action='apply-missing', granting_rules=['patch: x', 'create: y'],
            object_request=dict(namespace='team-a', resource_kind='configmaps', name='settings')))
        campaign.witness_request(report, self.spec)
        for grants in [['x'], ['patch: x'], ['create: y'], ['patch: ', 'create: y'], ['get: x', 'create: y']]:
            changed = copy.deepcopy(report); changed['counterexample']['granting_rules'] = grants
            with self.subTest(grants=grants), self.assertRaises(RuntimeError): campaign.witness_request(changed, self.spec)
        changed = copy.deepcopy(report); changed['counterexample']['action'] = 'apply-existing'
        with self.assertRaises(RuntimeError): campaign.witness_request(changed, self.spec)
        changed['counterexample']['granting_rules'] = ['patch: x']
        campaign.witness_request(changed, self.spec)

    def test_linked_module_and_method_identity_is_strict(self):
        versions = {'kubernetes': 'v1.34.0', 'apiserver': 'v0.34.0', 'api': 'v0.34.0', 'apimachinery': 'v0.34.0'}
        functions = {label: dict(function='k8s.io/'+module+'/'+function,
            file='k8s.io/'+module+'@'+versions[module]+'/'+source, line=line)
            for label, (module, source, line, function) in campaign.LINKAGE.items()}
        execution = dict(returncode=0, data=dict(schema_version=1, kind='rbac_apply_native_linkage', go_version='go1.24.0',
            modules={'k8s.io/'+module: version for module, version in versions.items()}, functions=functions))
        campaign.audit_linkage(execution)
        for mutation in ['module', 'method', 'source', 'line', 'bool-line', 'missing', 'extra', 'schema', 'exit', 'toolchain']:
            changed = copy.deepcopy(execution)
            data = changed['data']
            if mutation == 'module': data['modules']['k8s.io/apiserver'] = 'v0.35.0'
            elif mutation == 'method': data['functions']['patch-handler']['function'] = 'local.fakePatch'
            elif mutation == 'source': data['functions']['patch-handler']['file'] = 'local/fakePatch.go'
            elif mutation == 'line': data['functions']['patch-handler']['line'] = 99999
            elif mutation == 'bool-line': data['functions']['patch-handler']['line'] = True
            elif mutation == 'missing': data['functions'].pop('generic-store-update')
            elif mutation == 'extra': data['functions']['extra'] = {}
            elif mutation == 'schema': data['schema_version'] = True
            elif mutation == 'exit': changed['returncode'] = False
            else: data['go_version'] = ''
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_linkage(changed)

    def test_source_inventory_content_is_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots = {'kubernetes': root/'kubernetes@v1.34.0', 'apiserver': root/'apiserver@v0.34.0'}
            metadata = root/'modules.json'
            campaign.save(metadata, dict(Dir=str(roots['kubernetes'])))
            pins = {}
            for module, entries in campaign.SOURCE_FILES.items():
                pins[module] = {}
                for relative in entries:
                    path = roots[module]/relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(module+'/'+relative)
                    pins[module][relative] = campaign.digest(path)
            original_read = campaign.read_json
            def read(path): return copy.deepcopy(pins) if path == campaign.HERE/'source-pins.json' else original_read(path)
            with mock.patch.object(campaign, 'read_json', side_effect=read):
                self.assertEqual(len(campaign.source_provenance(metadata)), 28)
                victim = roots['apiserver']/campaign.SOURCE_FILES['apiserver'][0]
                victim.write_text('modified')
                with self.assertRaises(RuntimeError): campaign.source_provenance(metadata)
                pins['apiserver'].pop(campaign.SOURCE_FILES['apiserver'][0])
                with self.assertRaises(RuntimeError): campaign.source_provenance(metadata)

    def test_completion_requires_mode_exact_counts_inventory_and_stability(self):
        for mode in [False, True]:
            result = dict(native_only=mode, failures=[], inputs_unchanged=True, binaries_unchanged=True, native_linkage_verified=True, cases={}, **campaign.planned_counts(mode))
            for case in campaign.matrix_cases(): result['cases']['matrix/'+case['id']] = dict(matrix_comparisons=1650)
            for case in campaign.contract_cases():
                entry = dict(native_contract=case['expected'], native_comparison=case['comparison'])
                if not mode:
                    entry['contract'] = case['expected']
                    if case['baseline'] is not None: entry['comparison'] = case['comparison']
                result['cases']['contracts/'+case['id']] = entry
            campaign.audit_completion(result, mode)
            for field in campaign.planned_counts(mode):
                for value in [result[field]-1, result[field]+1, float(result[field]), True]:
                    changed = copy.deepcopy(result); changed[field] = value
                    with self.subTest(mode=mode, field=field, value=value), self.assertRaises(RuntimeError): campaign.audit_completion(changed, mode)
            for mutation in ['mode', 'case', 'case-result', 'source', 'binary', 'linkage', 'failure']:
                changed = copy.deepcopy(result)
                if mutation == 'mode': changed['native_only'] = not mode
                elif mutation == 'case': changed['cases'].pop('matrix/empty-policy')
                elif mutation == 'case-result': changed['cases']['contracts/unsafe-apply-create']['native_contract'] = 'proved'
                elif mutation == 'source': changed['inputs_unchanged'] = 1
                elif mutation == 'binary': changed['binaries_unchanged'] = False
                elif mutation == 'linkage': changed['native_linkage_verified'] = False
                else: changed['failures'] = ['problem']
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): campaign.audit_completion(changed, mode)

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
