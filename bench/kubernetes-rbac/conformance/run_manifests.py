#!/usr/bin/env python3
"""Synthetic manifest-ingestion conformance against Kubernetes v1.34.0."""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (CORPUS, PROFILE, decisions, digest, execute, module_provenance,
                 read_json, require, save, smt_decisions, strict_json, validate_report)
from run_preparation import (LIST_FIELDS, OBJECT_FIELDS, byte_hash,
                             validate_policy_comparison)


def audit_receipt(receipt, source, output, reference, namespace, selection):
    """Audit provenance against independently decoded ORIGINAL documents.

    Kubernetes supplies the expected normalized inventory. This traversal only
    accounts for source locations/defaults/removals; it never decides access.
    """
    require(set(receipt) == {'schema_version', 'kind', 'target_profile', 'input', 'snapshot',
        'object_count', 'removed_fields', 'verification_performed', 'completeness_established',
        'input_format', 'document_count', 'selection', 'namespace_context', 'empty_documents',
        'list_wrappers', 'retained_objects', 'excluded_objects', 'defaulted_fields'}, 'Receipt shape')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 2
            and receipt['kind'] == 'rbac-snapshot-preparation' and receipt['target_profile'] == PROFILE,
            'Receipt version/profile')
    require(receipt['verification_performed'] is False and receipt['completeness_established'] is False,
            'Preparation cannot establish verification/completeness')
    require(type(receipt['object_count']) is int and type(receipt['document_count']) is int,
            'Receipt counts must be integers')
    require(all(type(item['snapshot_index']) is int for item in receipt['retained_objects'])
            and all(type(item['item_count']) is int for item in receipt['list_wrappers']),
            'Receipt inventory indices/counts must be integers')
    for key, data in [('input', source), ('snapshot', output)]:
        require(type(receipt[key]['bytes']) is int, 'Receipt byte count must be integer')
        require(receipt[key] == dict(sha256=byte_hash(data), bytes=len(data)), 'Exact identity mismatch')
    require(receipt['namespace_context'] == namespace and receipt['selection'] == selection, 'Context mismatch')
    require(receipt['document_count'] == len(reference['documents']), 'Document count')
    retained, excluded, defaults, removed, wrappers, empty = [], [], [], [], [], []

    def visit(value, path, parent=None):
        if parent and not value.get('kind') and not value.get('apiVersion'):
            defaults.extend([dict(path=path+'.apiVersion', value=parent['apiVersion']),
                             dict(path=path+'.kind', value=parent['kind'][:-4])])
            kind, api = parent['kind'][:-4], parent['apiVersion']
        else:
            kind, api = value['kind'], value['apiVersion']
        metadata = value.get('metadata', {})
        if kind.endswith('List'):
            wrappers.append(dict(path=path, apiVersion=api, kind=kind, item_count=len(value['items'])))
            require(set(metadata) <= LIST_FIELDS, 'Unknown List metadata')
            removed.extend(path+'.metadata.'+key for key in metadata)
            for index, child in enumerate(value['items']):
                visit(child, f'{path}.items[{index}]', value if kind != 'List' else None)
        elif api == 'rbac.authorization.k8s.io/v1':
            retained.append(dict(source_path=path, snapshot_index=len(retained)))
            if namespace and kind in ['Role', 'RoleBinding'] and not metadata.get('namespace'):
                defaults.append(dict(path=path+'.metadata.namespace', value=namespace))
            removed.extend(path+'.metadata.'+key for key in metadata if key in OBJECT_FIELDS)
        else:
            excluded.append(dict(source_path=path, apiVersion=api, kind=kind))

    for index, value in enumerate(reference['documents']):
        path = f'documents[{index}]'
        if value is None:
            empty.append(path)
        else:
            visit(value, path)
    expected = dict(object_count=len(retained), retained_objects=retained, excluded_objects=excluded,
                    defaulted_fields=defaults, removed_fields=sorted(removed), list_wrappers=wrappers,
                    empty_documents=empty)
    for key, value in expected.items():
        require(receipt[key] == value, 'Provenance mismatch: '+key)
    normalized = copy.deepcopy(reference['snapshot'])
    for item in normalized['items']:
        for key in OBJECT_FIELDS:
            item['metadata'].pop(key, None)
    require(strict_json(output) == normalized, 'Output changed upstream-decoded retained data')
    require(output.endswith(b'\n') and not output.endswith(b'\n\n'), 'Snapshot newline')


def cases():
    rendered = (CORPUS/'preparation/manifests/rendered.yaml').read_bytes()
    yield 'rendered-yaml', 'yaml', rendered, 'frontend', True, 'violated'
    for name, verdict in [('01-unsafe', 'violated'), ('02-delete-workload-grants', 'violated'),
                          ('03-valid-repair', 'proved'), ('16-operator-regression', 'proved')]:
        items = read_json(CORPUS/'fixtures'/f'{name}.json')['items']
        source = '\n---\n'.join(json.dumps(item) for item in items).encode()
        yield name+'-stream', 'yaml', source, None, False, verdict
    source = read_json(CORPUS/'fixtures/01-unsafe.json')
    typed = dict(apiVersion='v1', kind='List', items=[])
    for kind in ['ClusterRole', 'RoleBinding']:
        children = []
        for obj in source['items']:
            if obj['kind'] == kind:
                obj = copy.deepcopy(obj)
                del obj['kind']; del obj['apiVersion']
                children.append(obj)
        typed['items'].append(dict(apiVersion='rbac.authorization.k8s.io/v1', kind=kind+'List', items=children))
    yield 'nested-typed-json', 'json', json.dumps(typed).encode(), None, False, 'violated'
    # Explicit RoleBinding namespace wins over --namespace; an omitted SA
    # namespace follows that binding. ClusterRoleBinding subjects stay explicit.
    boundary = copy.deepcopy(source)
    for item in boundary['items']:
        if item['metadata']['name'] == 'frontend-extra':
            del item['subjects'][0]['namespace']  # now payments:frontend-sa
    boundary['items'].append(dict(apiVersion='rbac.authorization.k8s.io/v1', kind='ClusterRoleBinding',
        metadata=dict(name='explicit-account-config'),
        roleRef=dict(apiGroup='rbac.authorization.k8s.io', kind='ClusterRole', name='config-reader'),
        subjects=[dict(kind='ServiceAccount', name='frontend-sa', namespace='frontend')]))
    yield 'subject-namespace-boundaries', 'json', json.dumps(boundary).encode(), 'default-context', False, 'proved'
    # The first empty document is explicit. A comment preamble before the first
    # '---' is not a YAML document, although Kubernetes' line reader can emit
    # it as an extra null chunk; do not confuse chunk indices with source docs.
    yield 'empty-yaml-docs', 'yaml', b'---\n# empty\n---\n'+rendered+b'---\n# trailing\n', 'frontend', True, 'violated'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference', 'model', 'soundcheck', 'module-metadata', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    z3 = shutil.which(args.z3)
    require(z3 is not None, 'Z3 is required')
    report = dict(complete=False, reference=module_provenance(args.module_metadata),
                  cases={}, matrix_comparisons=0, typed_policy_comparisons=0, receipt_controls=0,
                  input_sha256={}, failures=[],
                  binary_sha256={str(path): digest(path) for path in [args.reference, args.model, args.soundcheck, Path(z3)]},
                  limits=['Synthetic input-preparation acceptance, not public deployment benchmarking.',
                          'Finite concrete/SMT checks do not prove universal parser or model correctness.'])
    artifacts = args.output.parent/'artifacts'
    contract = CORPUS/'contracts/frontend-access.json'
    requests_file = CORPUS/'requests.json'
    requests = read_json(requests_file)
    report['input_sha256'].update({str(path): digest(path) for path in [contract, requests_file]})
    try:
        with tempfile.TemporaryDirectory(prefix='soundcheck-manifests-') as temporary:
            solver = Path(temporary, 'z3')
            solver.symlink_to(Path(z3).resolve())
            environment = dict(os.environ, PATH=temporary+os.pathsep+os.environ.get('PATH', ''))
            for name, format_, source, namespace, rbac_only, verdict in cases():
                folder = artifacts/name
                folder.mkdir(parents=True, exist_ok=True)
                original = folder/('source.'+format_)
                original.write_bytes(source)
                report['input_sha256'][str(original)] = digest(original)
                decoded = execute([args.reference, '--manifest-reference', format_, namespace or '', original],
                                  folder/'native-decode.json', environment)
                require(decoded['returncode'] == 0, 'Reference decode failed')
                native = decoded['data']
                require(set(native) == {'schema_version', 'kind', 'source_sha256', 'documents', 'snapshot'}
                        and type(native['schema_version']) is int and native['schema_version'] == 1
                        and native['kind'] == 'upstream_manifest_reference'
                        and native['source_sha256'] == byte_hash(source), 'Reference input binding')
                native_path = folder/'native-snapshot.json'
                save(native_path, native['snapshot'])
                receipt_path = Path(temporary, name+'-receipt.json')
                command = [args.soundcheck, 'rbac', 'prepare', original, '--input-format', format_, '--receipt', receipt_path]
                if namespace:
                    command += ['--namespace', namespace]
                if rbac_only:
                    command += ['--rbac-only']
                prepared = execute(command, folder/'prepare.json', environment)
                require(prepared['returncode'] == 0, 'Preparation failed: '+name)
                output = prepared['stdout'].encode()
                target = folder/'prepared.json'
                target.write_bytes(output)
                receipt = read_json(receipt_path)
                save(folder/'receipt.json', receipt)
                require(receipt['input_format'] == format_, 'Receipt format')
                audit_receipt(receipt, source, output, native, namespace, 'rbac-only' if rbac_only else 'all')
                comparison = execute([args.reference, '--compare-policies', native_path, target],
                                     folder/'typed-policy.json', environment)
                validate_policy_comparison(comparison, native_path.read_bytes(), output)
                report['typed_policy_comparisons'] += 1
                before = execute([args.reference, native_path, requests_file], folder/'original-decisions.json', environment)
                after = execute([args.reference, target, requests_file], folder/'prepared-decisions.json', environment)
                model = execute([args.model, target, contract, requests_file], folder/'model.json', environment)
                require(decisions(before, requests, 'reference') == decisions(after, requests, 'reference')
                        == decisions(model, requests, 'model')
                        == smt_decisions(model, requests, folder, 'matrix', z3, environment), 'Authorization changed')
                verified = execute([args.soundcheck, 'rbac', 'verify', target, '--contract', contract, '--format', 'json'],
                                   folder/'verify.json', environment)
                validate_report(verified, read_json(contract), verdict)
                report['matrix_comparisons'] += len(requests)
                report['cases'][name] = dict(objects=receipt['object_count'], excluded=len(receipt['excluded_objects']),
                                            prepared_sha256=byte_hash(output), contract=verdict)
                # Audit controls must catch incomplete or fabricated provenance.
                for key in ['retained_objects', 'defaulted_fields', 'removed_fields', 'excluded_objects']:
                    if receipt[key]:
                        corrupted = copy.deepcopy(receipt)
                        corrupted[key] = corrupted[key][1:]
                        try:
                            audit_receipt(corrupted, source, output, native, namespace, 'rbac-only' if rbac_only else 'all')
                        except RuntimeError:
                            report['receipt_controls'] += 1
                        else:
                            raise RuntimeError('Corrupted receipt accepted: '+key)
                corrupted = copy.deepcopy(receipt)
                corrupted['retained_objects'][0]['snapshot_index'] = False
                try:
                    audit_receipt(corrupted, source, output, native, namespace, 'rbac-only' if rbac_only else 'all')
                except RuntimeError:
                    report['receipt_controls'] += 1
                else:
                    raise RuntimeError('Boolean substituted for receipt index')
                save(args.output, report)
                print(f'{name}: {receipt["object_count"]} RBAC objects, {verdict}', flush=True)
        require(all(digest(Path(path)) == value for path, value in report['input_sha256'].items()), 'Original input changed')
        require(all(digest(Path(path)) == value for path, value in report['binary_sha256'].items()), 'Tool binary changed')
        report['complete'] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        report['failures'].append(str(error))
    save(args.output, report)
    print({key: report[key] for key in ['complete', 'typed_policy_comparisons', 'matrix_comparisons', 'receipt_controls', 'failures']})
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
