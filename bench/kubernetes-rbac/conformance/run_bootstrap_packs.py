#!/usr/bin/env python3
"""Audit explicit bootstrap pack preparation against pinned native Kubernetes.

No solver, cluster or live policy update is involved. All 15 nonempty selections
must retain the native typed policy and accurately report reference assumptions.
"""
import argparse
import itertools
import os
import tempfile
from pathlib import Path

from run import (CORPUS, digest, execute, module_provenance, read_json, require,
                 save, strict_json)
from run_inventory import encoded, identity
from run_manifests import audit_receipt as audit_manifest
from run_preparation import validate_policy_comparison

HERE = Path(__file__).resolve().parent
PACKS = CORPUS/'bootstrap-packs'
NAMES = ['auth-delegator', 'cluster-admin', 'extension-apiserver-authentication-reader', 'view']
SOURCE_FILES = [
    'plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go',
    'plugin/pkg/auth/authorizer/rbac/bootstrappolicy/namespace_policy.go',
    'plugin/pkg/auth/authorizer/rbac/bootstrappolicy/controller_policy.go',
    'pkg/registry/rbac/rest/storage_rbac.go',
    'pkg/controller/clusterroleaggregation/clusterroleaggregation_controller.go',
    'pkg/features/kube_features.go',
]


def audit_receipt(receipt, source, selected, output, original, native):
    require(set(receipt) == {'schema_version', 'kind', 'kubernetes_version', 'requested_packs',
        'selected_packs', 'reference', 'upstream', 'configuration', 'source_catalogue', 'objects',
        'normalization', 'snapshot', 'object_count', 'verification_performed',
        'installed_state_observed', 'identity_authentication_established', 'completeness_established',
        'limitations'}, 'Bootstrap receipt shape')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1 and
            receipt['kind'] == 'rbac-bootstrap-selection' and receipt['kubernetes_version'] == '1.34.0',
            'Bootstrap receipt protocol')
    catalogue = strict_json(source)
    require(receipt['reference'] == identity(source), 'Exact embedded reference hash')
    require(receipt['snapshot'] == identity(output), 'Exact emitted snapshot hash/newline')
    for key in ['reference', 'snapshot']:
        require(type(receipt[key]['bytes']) is int, 'Byte counts must be integers')
    require(receipt['requested_packs'] == selected and receipt['selected_packs'] == sorted(selected),
            'Explicit selection order')
    for key in ['upstream', 'configuration', 'source_catalogue']:
        require(receipt[key] == catalogue[key], 'Reference provenance mismatch: '+key)
    for key in ['verification_performed', 'installed_state_observed',
                'identity_authentication_established', 'completeness_established']:
        require(receipt[key] is False, 'Bootstrap selection cannot establish '+key)
    rows = {p['name']: p for p in catalogue['packs']}
    objects = []
    for name in sorted(selected):
        for key, reason in [('requested_objects', 'requested'), ('dependency_objects', 'aggregation-dependency')]:
            objects += [dict(identity=obj, pack=name, selection=reason) for obj in rows[name][key]]
    require(receipt['objects'] == objects, 'Requested/dependency object accounting')
    require(type(receipt['object_count']) is int and receipt['object_count'] == len(objects), 'Object count')
    require(isinstance(receipt['limitations'], list) and len(receipt['limitations']) == 5 and
            all(isinstance(s, str) and s for s in receipt['limitations']), 'Explicit assumption limitations')
    require(len(strict_json(output)['items']) == len(objects), 'Unexpected extra or missing output objects')
    require(all(obj['kind'] in ['Role', 'ClusterRole'] for obj in strict_json(output)['items']),
            'Bootstrap pack must not synthesize bindings or identities')
    audit_manifest(receipt['normalization'], original, output, native, None, 'all')


def source_provenance(metadata):
    root = Path(read_json(metadata)['Dir'])
    pins = read_json(PACKS/'source-pins.json')
    require(set(pins) == set(SOURCE_FILES), 'Unexpected pinned native source inventory')
    for relative in SOURCE_FILES:
        require(digest(root/relative) == pins[relative], 'Pinned native source differs: '+relative)
    return {str(root/relative): pins[relative] for relative in SOURCE_FILES}


def audit_completion(report):
    require(report['failures'] == [], 'Bootstrap failures present')
    require(type(report['selections']) is int and report['selections'] == 15, 'Incomplete pack selections')
    require(type(report['typed_policy_comparisons']) is int and report['typed_policy_comparisons'] == 15,
            'Incomplete native policy comparison')
    require(type(report['receipt_audits']) is int and report['receipt_audits'] == 15,
            'Incomplete receipt auditing')
    require(report['native_generation_equal'] is True, 'Native bootstrap regeneration mismatch')
    require(report['installed_state_observed'] is False and report['verification_performed'] is False,
            'Bootstrap conformance is not deployment verification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ['reference', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+key, type=Path, required=True)
    args = parser.parse_args()
    for key, value in vars(args).items():
        setattr(args, key, value.resolve())
    report = dict(complete=False, failures=[], selections=0, typed_policy_comparisons=0,
                  receipt_audits=0, native_generation_equal=False, installed_state_observed=False,
                  verification_performed=False, cases={}, reference=module_provenance(args.module_metadata))
    environment = dict(os.environ)
    artifacts = args.output.parent/'artifacts'
    artifact = PACKS/'kubernetes-v1.34.0.json'
    fixed = [artifact, PACKS/'source-pins.json', PACKS/'provenance.json', PACKS/'KUBERNETES-LICENSE',
             PACKS/'generate.py', HERE/'run_bootstrap_packs.py', HERE/'test_bootstrap_packs_runner.py',
             HERE/'oracle/bootstrap_pack_reference.go', HERE/'oracle/bootstrap_pack_reference_test.go']
    report['input_sha256'] = {str(p): digest(p) for p in fixed}
    report['binary_sha256'] = {str(p): digest(p) for p in [args.reference, args.soundcheck]}
    try:
        report['upstream_source_sha256'] = source_provenance(args.module_metadata)
        source = artifact.read_bytes()
        provenance = read_json(PACKS/'provenance.json')
        require(provenance['artifact_sha256'] == digest(artifact), 'Artifact provenance hash')
        catalogue = strict_json(source)
        require([pack['name'] for pack in catalogue['packs']] == NAMES, 'Pinned pack inventory')
        generated = execute([args.reference, '--bootstrap-pack-reference'], artifacts/'native-generation.json', environment)
        require(generated['returncode'] == 0 and generated['stdout'].encode() == source,
                'Native default policy/controller regeneration differs from embedded reference')
        report['native_generation_equal'] = True
        rows = {pack['name']: pack for pack in catalogue['packs']}
        for count in range(1, len(NAMES)+1):
            for selected in itertools.combinations(NAMES, count):
                selected = list(selected)
                label = '+'.join(selected)
                folder = artifacts/label
                folder.mkdir(parents=True, exist_ok=True)
                original = encoded(dict(apiVersion='v1', kind='List',
                    items=[item for name in selected for item in rows[name]['objects']]))
                original_path = folder/'original.json'
                original_path.write_bytes(original)
                argv = [args.soundcheck, 'rbac', 'bootstrap', '--kubernetes-version', '1.34.0']
                for name in selected:
                    argv += ['--pack', name]
                # The CLI deliberately requires a NEW private receipt file.
                # A fresh path keeps rerunning this conformance suite valid;
                # retain the exact emitted bytes with the ordinary artifacts.
                with tempfile.TemporaryDirectory(prefix='soundcheck-bootstrap-selection-') as temporary:
                    receipt_path = Path(temporary)/'receipt.json'
                    prepared = execute(argv+['--receipt', receipt_path], folder/'prepare.json', environment)
                    require(prepared['returncode'] == 0, 'Bootstrap selection failed: '+label)
                    receipt_bytes = receipt_path.read_bytes()
                (folder/'receipt.json').write_bytes(receipt_bytes)
                output = prepared['stdout'].encode()
                output_path = folder/'snapshot.json'
                output_path.write_bytes(output)
                native = execute([args.reference, '--manifest-reference', 'json', '', original_path],
                                 folder/'native-original.json', environment)
                require(native['returncode'] == 0 and native['data']['kind'] == 'upstream_manifest_reference' and
                        native['data']['source_sha256'] == identity(original)['sha256'],
                        'Native original pack decoding failed')
                comparison = execute([args.reference, '--compare-policies', original_path, output_path],
                                     folder/'native-policy.json', environment)
                validate_policy_comparison(comparison, original, output)
                audit_receipt(strict_json(receipt_bytes), source, selected, output, original, native['data'])
                report['cases'][label] = dict(objects=len(prepared['data']['items']),
                    policy_sha256=comparison['data']['original_policy_sha256'], snapshot_sha256=digest(output_path))
                report['selections'] += 1
                report['typed_policy_comparisons'] += 1
                report['receipt_audits'] += 1
        for collection in ['input_sha256', 'binary_sha256', 'upstream_source_sha256']:
            require(all(digest(Path(path)) == sha for path, sha in report[collection].items()),
                    'Files changed during bootstrap audit: '+collection)
        audit_completion(report)
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        report['failures'].append(str(error))
        raise
    finally:
        save(args.output, report)
    print('Bootstrap packs: 15 native policy comparisons and receipt audits passed')


if __name__ == '__main__':
    main()
