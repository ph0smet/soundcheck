#!/usr/bin/env python3
"""Explicitly freeze source-derived controller expectations before evaluation."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'conformance'))
import run_controller_apis as campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubernetes-source', type=Path, required=True)
    args = parser.parse_args()
    kube = args.kubernetes_source.resolve()
    roots = {'kubernetes': kube, 'apiserver': kube.parent/'apiserver@v0.34.0',
             'apiextensions-apiserver': kube.parent/'apiextensions-apiserver@v0.34.0'}
    inputs = campaign.planned_inputs()
    campaign.HERE.mkdir(parents=True, exist_ok=True)
    campaign.save(campaign.HERE/'inputs.json', {name: {'sha256': campaign.byte_hash(data), 'bytes': len(data)} for name, data in inputs.items()})
    (campaign.HERE/'contract.json').write_bytes(inputs['contract.json'])
    campaign.save(campaign.HERE/'source-pins.json', {module: {relative: campaign.digest(roots[module]/relative) for relative in paths}
        for module, paths in campaign.SOURCE_FILES.items()})
    print(f'Frozen {len(inputs)} synthetic artifacts; no verifier or solver executed.')


if __name__ == '__main__':
    main()
