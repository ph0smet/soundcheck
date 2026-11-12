#!/usr/bin/env python3
"""Freeze reviewed synthetic inputs and pinned native sources; executes no tool.

This is an explicit maintainer operation, never a conformance-test repair step.
Review changed semantics before regenerating expectations or their digests.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'conformance'))
import run_apply as campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubernetes-source', required=True, type=Path)
    args = parser.parse_args()
    kube = args.kubernetes_source.resolve()
    roots = dict(kubernetes=kube, apiserver=kube.parent/'apiserver@v0.34.0')
    inputs = campaign.planned_inputs()
    campaign.HERE.mkdir(parents=True, exist_ok=True)
    campaign.save(campaign.HERE/'inputs.json', {path: dict(sha256=campaign.byte_hash(value), bytes=len(value)) for path, value in inputs.items()})
    (campaign.HERE/'contract.json').write_bytes(inputs['contract.json'])
    campaign.save(campaign.HERE/'source-pins.json', {
        module: {relative: campaign.digest(roots[module]/relative) for relative in relatives}
        for module, relatives in campaign.SOURCE_FILES.items()})
    print(f'Frozen {len(inputs)} synthetic artifacts; no verifier or solver executed.')


if __name__ == '__main__':
    main()
