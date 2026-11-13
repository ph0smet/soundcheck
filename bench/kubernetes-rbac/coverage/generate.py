#!/usr/bin/env python3
"""Explicitly freeze independently reviewed inputs; never regenerate on failure."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'conformance'))
import run_coverage as campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubernetes-source', type=Path, required=True)
    args = parser.parse_args()
    kube = args.kubernetes_source.resolve()
    roots = dict(kubernetes=kube, apiserver=kube.parent/'apiserver@v0.34.0')
    inputs = campaign.planned_inputs()
    campaign.HERE.mkdir(parents=True, exist_ok=True)
    campaign.save(campaign.HERE/'inputs.json', {path: dict(sha256=campaign.byte_hash(value), bytes=len(value)) for path, value in inputs.items()})
    (campaign.HERE/'contract.json').write_bytes(inputs['contract.json'])
    campaign.save(campaign.HERE/'source-pins.json', {module: {relative: campaign.digest(roots[module]/relative) for relative in relatives}
        for module, relatives in campaign.SOURCE_FILES.items()})
    print(f'Frozen {len(inputs)} synthetic artifacts; no verifier or solver executed.')


if __name__ == '__main__':
    main()
