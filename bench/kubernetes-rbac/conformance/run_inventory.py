#!/usr/bin/env python3
"""Explicit multi-source inventory and frozen-identity acceptance against Kubernetes."""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, PROFILE, decisions, digest, execute, module_provenance,
                 read_json, require, save, smt_decisions, strict_json)
from run_manifests import audit_receipt as audit_manifest
from run_preparation import OBJECT_FIELDS, byte_hash, validate_policy_comparison
from run_read_access import scope_matches
from run_write_access import normalize_contract, validate_report, witness_request


def identity(data):
    return dict(sha256=byte_hash(data), bytes=len(data))


def encoded(value):
    return (json.dumps(value, separators=(',', ':'))+'\n').encode()


def audit_receipt(receipt, plan_bytes, sources, natives, output):
    plan = strict_json(plan_bytes)
    require(set(receipt) == {'schema_version', 'kind', 'target_profile', 'plan', 'sources',
        'snapshot', 'object_count', 'objects', 'assumed_bootstrap_sources',
        'verification_performed', 'source_authenticity_established', 'completeness_established'}, 'Inventory receipt shape')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['kind'] == 'rbac-inventory-assembly' and receipt['target_profile'] == PROFILE, 'Receipt protocol')
    for flag in ['verification_performed', 'source_authenticity_established', 'completeness_established']:
        require(receipt[flag] is False, 'Receipt trust claim: '+flag)
    require(receipt['plan'] == identity(plan_bytes) and receipt['snapshot'] == identity(output), 'Receipt exact-byte identities')
    require(type(receipt['plan']['bytes']) is int and type(receipt['snapshot']['bytes']) is int, 'Integer byte counts')
    require(len(receipt['sources']) == len(plan['sources']) == len(sources) == len(natives), 'Source accounting')
    items, origins = [], []
    for descriptor, source, native, entry in zip(plan['sources'], sources, natives, receipt['sources']):
        require(set(entry) == {'id', 'path', 'source_type', 'declared_source_version', 'normalization'}, 'Source receipt shape')
        for key in ['id', 'path', 'source_type']:
            require(entry[key] == descriptor[key], 'Source declaration mismatch: '+key)
        require(entry['declared_source_version'] == descriptor.get('source_version'), 'Source version declaration')
        require(descriptor['sha256'] == byte_hash(source), 'Plan source pin')
        normalized = copy.deepcopy(native['snapshot'])
        for item in normalized['items']:
            for key in OBJECT_FIELDS:
                item['metadata'].pop(key, None)
        fragment = copy.deepcopy(entry['normalization'])
        require(set(fragment) == {'input', 'object_count', 'removed_fields', 'input_format', 'document_count',
            'selection', 'namespace_context', 'empty_documents', 'list_wrappers', 'retained_objects',
            'excluded_objects', 'defaulted_fields'}, 'Fragment provenance shape; no standalone snapshot/trust claims')
        # Reuse the independent original-document traversal. This adapter only
        # renames fragment-local indices; it does not validate a partial snapshot.
        for retained in fragment['retained_objects']:
            require(set(retained) == {'source_path', 'object_index'} and type(retained['object_index']) is int,
                    'Fragment source index')
            retained['snapshot_index'] = retained.pop('object_index')
        fragment.update(schema_version=2, kind='rbac-snapshot-preparation', target_profile=PROFILE,
                        snapshot=identity(encoded(normalized)), verification_performed=False, completeness_established=False)
        audit_manifest(fragment, source, encoded(normalized), native, descriptor.get('namespace'),
                       'rbac-only' if descriptor.get('rbac_only', False) else 'all')
        require(fragment['input_format'] == descriptor['format'], 'Source format')
        for retained, item in zip(fragment['retained_objects'], normalized['items']):
            metadata = item['metadata']
            origins.append(dict(snapshot_index=len(items), source_id=descriptor['id'],
                source_path=retained['source_path'], identity=dict(kind=item['kind'], name=metadata['name'],
                                                                namespace=metadata.get('namespace', ''))))
            items.append(item)
    require(type(receipt['object_count']) is int and receipt['object_count'] == len(items), 'Object count')
    require(all(type(obj['snapshot_index']) is int for obj in receipt['objects']), 'Output indices')
    require(receipt['objects'] == origins, 'Source-to-output mapping')
    require(strict_json(output) == dict(apiVersion='v1', kind='List', items=items), 'All native objects retained in source order')
    require(receipt['assumed_bootstrap_sources'] == [s['id'] for s in plan['sources']
            if s['source_type'] == 'bootstrap-reference'], 'Explicit bootstrap assumptions')


def requests_for(contract):
    requests = []
    for user in contract['context']['identities']:
        for verb in ['get', 'list', 'watch', 'update', 'patch', 'delete']:
            collection = verb in ['list', 'watch']
            for namespace in ['kube-system', 'demo', 'unseen'] + ([''] if collection else []):
                for resource in ['configmaps', 'secrets']:
                    for name in ['extension-apiserver-authentication', 'other'] + ([''] if collection else []):
                        requests.append(dict(id=str(len(requests)), **user, verb=verb, apiGroup='', resource=resource,
                                             namespace=namespace, name=name, subresource='', resourceRequest=True))
    return requests


def extra_source():
    return dict(apiVersion='v1', kind='List', items=[
        dict(apiVersion='rbac.authorization.k8s.io/v1', kind='ClusterRole', metadata=dict(name='extra-secrets'),
             rules=[dict(apiGroups=[''], resources=['secrets'], verbs=['get'])]),
        dict(apiVersion='rbac.authorization.k8s.io/v1', kind='ClusterRoleBinding', metadata=dict(name='extra-authenticated'),
             roleRef=dict(apiGroup='rbac.authorization.k8s.io', kind='ClusterRole', name='extra-secrets'),
             subjects=[dict(kind='Group', apiGroup='rbac.authorization.k8s.io', name='system:authenticated')])])


def audit_inspection(inspected, snapshot, contract_bytes, case):
    contract = strict_json(contract_bytes)
    require(set(inspected) == {'schema_version', 'kind', 'target_profile', 'snapshot', 'contract',
        'contract_version', 'canonical_contract', 'canonical_contract_sha256', 'identity_source', 'identities',
        'snapshot_completeness_asserted_by_contract', 'identity_authentication_established',
        'completeness_established', 'authorization_evaluated', 'verification_performed'}, 'Inspection shape')
    require(type(inspected['schema_version']) is int and inspected['schema_version'] == 1
            and inspected['kind'] == 'rbac-identity-inspection' and inspected['contract_version'] == 3
            and inspected['target_profile'] == 'kubernetes-rbac-v1.34-read-write-v3', 'Inspection protocol')
    require(inspected['snapshot'] == identity(snapshot) and inspected['contract'] == identity(contract_bytes), 'Inspection identities')
    require(inspected['canonical_contract_sha256'] == byte_hash(inspected['canonical_contract'].encode())
            and normalize_contract(strict_json(inspected['canonical_contract'])) == normalize_contract(contract), 'Inspection frozen contract')
    require(inspected['identity_source'] == 'frozen-contract'
            and inspected['snapshot_completeness_asserted_by_contract'] is True, 'Inspection assumption source')
    for field in ['verification_performed', 'authorization_evaluated', 'identity_authentication_established', 'completeness_established']:
        require(inspected[field] is False, 'Inspection trust claim')
    expected_users = sorted(contract['context']['identities'], key=lambda u: u['username'])
    require([u['username'] for u in inspected['identities']] == [u['username'] for u in expected_users],
            'Exact unique frozen username inventory')
    for user, expected in zip(inspected['identities'], expected_users):
        require(set(user) == {'username', 'groups', 'subject_matching_bindings'} and user['groups'] == sorted(expected['groups']),
                'Inspection inferred identity groups')
        matches = []
        if user['username'] == 'system:serviceaccount:demo:extension':
            subject = dict(kind='ServiceAccount', namespace='demo', name='extension')
            matches = [dict(binding='RoleBinding/kube-system/extension-authentication-reader',
                role='Role/kube-system/extension-apiserver-authentication-reader', rule_count=1, matching_subjects=[subject]),
                dict(binding='ClusterRoleBinding/extension-auth-delegator', role='ClusterRole/system:auth-delegator',
                     rule_count=2, matching_subjects=[subject])]
        if case == 'additional-group-grant':
            matches.append(dict(binding='ClusterRoleBinding/extra-authenticated', role='ClusterRole/extra-secrets',
                rule_count=1, matching_subjects=[dict(kind='Group', name='system:authenticated')]))
        require(all(type(m['rule_count']) is int for m in user['subject_matching_bindings']), 'Integer rule counts')
        require(user['subject_matching_bindings'] == matches, 'Exact binding/role/subject matches')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path): setattr(args, key, value.resolve())
    z3 = shutil.which(args.z3)
    require(z3 is not None, 'Z3 required')
    corpus = CORPUS/'inventory'
    report = dict(complete=False, reference=module_provenance(args.module_metadata), cases={},
        matrix_comparisons=0, typed_policy_comparisons=0, receipt_controls=0, rejected_plans=0,
        contract_witness_replays=0, inspection_controls=0, failures=[], input_sha256={},
        binary_sha256={str(path): digest(path) for path in [args.reference, args.model, args.soundcheck, Path(z3)]},
        limits=['Synthetic offline inventory; no claim about an installed cluster or complete bootstrap catalog.',
                'Exact groups and inventory completeness are external assumptions.',
                'Finite conformance checks are not a universal proof of parser/model correctness.'])
    artifacts = args.output.parent/'artifacts'
    try:
        artifacts.mkdir(parents=True, exist_ok=True)
        generated = execute([args.reference, '--bootstrap-reference'], artifacts/'generated.json', os.environ)
        require(generated['returncode'] == 0, 'Native bootstrap generation failed')
        bootstrap = corpus/'bootstrap-v1.34.0.json'
        require(generated['stdout'].encode() == bootstrap.read_bytes(), 'Reference excerpt differs from pinned upstream')
        provenance = read_json(corpus/'bootstrap-provenance.json')
        pins = read_json(Path(__file__).parent/'oracle/module-pins.json')
        require(provenance['artifact'] == bootstrap.name and provenance['sha256'] == digest(bootstrap)
                and provenance['upstream_module'] == pins['upstream_module']
                and provenance['upstream_commit'] == pins['upstream_commit']
                and provenance['upstream_module_sum'] == pins['upstream_module_sum'], 'Bootstrap provenance')
        require(provenance['objects'] == ['Role/kube-system/extension-apiserver-authentication-reader',
                                         'ClusterRole/system:auth-delegator'], 'Bootstrap selection')
        for path in corpus.iterdir():
            if path.is_file(): report['input_sha256'][str(path)] = digest(path)
        with tempfile.TemporaryDirectory(prefix='soundcheck-inventory-') as temporary:
            solver = Path(temporary, 'z3'); solver.symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=temporary+os.pathsep+os.environ.get('PATH', ''))
            for case in ['explicit-bootstrap', 'additional-group-grant', 'explicit-empty-groups']:
                folder = artifacts/case; folder.mkdir(parents=True, exist_ok=True)
                plan = read_json(corpus/'plan.json')
                contract = read_json(corpus/'contract.json')
                for descriptor in plan['sources']:
                    descriptor['path'] = str((corpus/descriptor['path']).resolve())
                if case != 'explicit-bootstrap':
                    additional = folder/'additional.json'; save(additional, extra_source())
                    plan['sources'].append(dict(id='additional', path=str(additional), sha256=digest(additional),
                                                format='json', source_type='supplied'))
                if case == 'explicit-empty-groups':
                    for user in contract['context']['identities']: user['groups'] = []
                expected = 'violated' if case == 'additional-group-grant' else 'proved'
                plan_path = folder/'plan.json'; save(plan_path, plan)
                contract_path = folder/'contract.json'; save(contract_path, contract)
                sources, natives, original_items = [], [], []
                for descriptor in plan['sources']:
                    path = Path(descriptor['path']); sources.append(path.read_bytes())
                    decoded = execute([args.reference, '--manifest-reference', descriptor['format'],
                        descriptor.get('namespace', ''), path], folder/(descriptor['id']+'-native.json'), environment)
                    require(decoded['returncode'] == 0 and decoded['data']['source_sha256'] == digest(path), 'Native source decode')
                    natives.append(decoded['data']); original_items.extend(decoded['data']['snapshot']['items'])
                native_path = folder/'native-union.json'
                save(native_path, dict(apiVersion='v1', kind='List', items=original_items))
                receipt_path = Path(temporary, case+'-receipt.json')
                assembled = execute([args.soundcheck, 'rbac', 'inventory', plan_path, '--receipt', receipt_path],
                                    folder/'assemble.json', environment)
                require(assembled['returncode'] == 0, 'Assembly failed')
                output = assembled['stdout'].encode(); snapshot = folder/'snapshot.json'; snapshot.write_bytes(output)
                receipt = read_json(receipt_path); save(folder/'receipt.json', receipt)
                audit_receipt(receipt, plan_path.read_bytes(), sources, natives, output)
                compared = execute([args.reference, '--compare-policies', native_path, snapshot], folder/'typed-policy.json', environment)
                validate_policy_comparison(compared, native_path.read_bytes(), output)
                report['typed_policy_comparisons'] += 1
                requests = requests_for(contract); requests_path = folder/'requests.json'; save(requests_path, requests)
                original = execute([args.reference, native_path, requests_path], folder/'original-decisions.json', environment)
                prepared = execute([args.reference, snapshot, requests_path], folder/'prepared-decisions.json', environment)
                model = execute([args.model, snapshot, contract_path, requests_path], folder/'model.json', environment)
                target = decisions(original, requests, 'reference')
                require(target == decisions(prepared, requests, 'reference') == decisions(model, requests, 'model')
                        == smt_decisions(model, requests, folder, 'matrix', z3, environment), 'Authorization disagreement')
                # Literal independently selected expectations guard against a
                # vacuous matrix or an accidentally unused bootstrap source.
                for request in requests:
                    reader = (request['username'] == 'system:serviceaccount:demo:extension'
                              and request['verb'] in ['get', 'list', 'watch'] and request['namespace'] == 'kube-system'
                              and request['resource'] == 'configmaps' and request['name'] == 'extension-apiserver-authentication')
                    extra = (case == 'additional-group-grant' and request['resource'] == 'secrets' and request['verb'] == 'get')
                    require(target[request['id']] == ('Allow' if reader or extra else 'NoOpinion'), 'Expected bootstrap/group decision')
                report['matrix_comparisons'] += len(requests)
                verified = execute([args.soundcheck, 'rbac', 'verify', snapshot, '--contract', contract_path, '--format', 'json'],
                                   folder/'verify.json', environment)
                verdict = validate_report(verified, contract, expected)
                if expected == 'violated':
                    clause = verdict.get('clause')
                    require(isinstance(clause, dict), 'Missing violated clause')
                    selected = [c for c in contract['clauses'] if c['name'] == clause.get('name')]
                    require(len(selected) == 1 and clause.get('kind') == selected[0]['kind']
                            and clause['name'] == 'secrets-not-granted', 'Wrong ordered failing clause')
                    witness = witness_request(verdict, {u['username']:u['groups'] for u in contract['context']['identities']})
                    require(scope_matches(selected[0], witness), 'Witness outside frozen clause')
                    witness_path = folder/'witness.json'; save(witness_path, [witness])
                    replay = execute([args.reference, native_path, witness_path], folder/'witness-replay.json', environment)
                    require(decisions(replay, [witness], 'reference')['witness'] == 'Allow', 'Counterexample replay')
                    report['contract_witness_replays'] += 1
                inspection = execute([args.soundcheck, 'rbac', 'inspect', snapshot, '--contract', contract_path],
                                     folder/'inspect.json', environment)
                require(inspection['returncode'] == 0, 'Inspection failed')
                inspected = inspection['data']
                audit_inspection(inspected, output, contract_path.read_bytes(), case)
                for mutate in [lambda r: r['identities'].clear(), lambda r: r['identities'].append(r['identities'][0]),
                    lambda r: r['identities'][0]['groups'].append('invented-group'),
                    lambda r: r['identities'][0]['subject_matching_bindings'][0].update(role='ClusterRole/fabricated'),
                    lambda r: r.update(identity_authentication_established=True)]:
                    bad = copy.deepcopy(inspected); mutate(bad)
                    try: audit_inspection(bad, output, contract_path.read_bytes(), case)
                    except RuntimeError: report['inspection_controls'] += 1
                    else: raise RuntimeError('Fabricated inspection accepted')
                for mutate in [lambda r: r['sources'].reverse(), lambda r: r['objects'].pop(),
                    lambda r: r['sources'][0]['normalization']['input'].update(sha256='0'*64),
                    lambda r: r['sources'][1].update(declared_source_version='v0.0.0'),
                    lambda r: r.update(completeness_established=True), lambda r: r['assumed_bootstrap_sources'].clear(),
                    lambda r: r['sources'][0]['normalization'].update(completeness_established=True),
                    lambda r: r['sources'][0]['normalization'].update(snapshot=identity(output))]:
                    bad = copy.deepcopy(receipt); mutate(bad)
                    try: audit_receipt(bad, plan_path.read_bytes(), sources, natives, output)
                    except RuntimeError: report['receipt_controls'] += 1
                    else: raise RuntimeError('Fabricated inventory receipt accepted')
                report['cases'][case] = dict(objects=receipt['object_count'], verdict=expected, requests=len(requests))
                print(f'{case}: {expected}, {len(requests)} finite decisions', flush=True)
            # No implicit bootstrap, collisions, pin bypass, or partial receipt.
            original_plan = read_json(artifacts/'explicit-bootstrap/plan.json')
            for label in ['missing-bootstrap', 'duplicate-role', 'changed-pin']:
                bad = copy.deepcopy(original_plan)
                if label == 'missing-bootstrap': bad['sources'] = bad['sources'][:1]
                elif label == 'duplicate-role': bad['sources'].append({**bad['sources'][1], 'id':'duplicate'})
                else: bad['sources'][1]['sha256'] = '0'*64
                path = artifacts/(label+'-plan.json'); save(path, bad)
                receipt = Path(temporary, label+'.json')
                rejected = execute([args.soundcheck, 'rbac', 'inventory', path, '--receipt', receipt],
                                   artifacts/(label+'.json'), environment, json_output=False)
                require(rejected['returncode'] == 2 and rejected['stdout'] == '' and not receipt.exists(), 'Rejected plan published output')
                if label == 'missing-bootstrap':
                    require(all(name in rejected['stderr'] for name in ['Role/kube-system/extension-apiserver-authentication-reader',
                        'ClusterRole/system:auth-delegator', 'documents[0]', 'documents[1]']), 'Missing-reference diagnostic incomplete')
                report['rejected_plans'] += 1
        require(all(digest(Path(path)) == value for path, value in report['input_sha256'].items()), 'Corpus changed')
        require(all(digest(Path(path)) == value for path, value in report['binary_sha256'].items()), 'Tool binary changed')
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print({key: report[key] for key in ['complete', 'matrix_comparisons', 'receipt_controls', 'rejected_plans', 'failures']})
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
