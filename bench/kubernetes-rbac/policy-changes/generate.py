#!/usr/bin/env python3
"""Explicit corpus preparation; never called by an acceptance run."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'conformance'))
import run_policy_changes as campaign


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-cache',type=Path,required=True)
    args=parser.parse_args()
    pins={}
    for module,files in campaign.SOURCE_FILES.items():
        version='v1.34.0' if module=='kubernetes' else 'v0.34.0'
        root=args.module_cache/'k8s.io'/(module+'@'+version)
        pins[module]={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
    campaign.save(HERE/'source-pins.json',pins)
    inputs=campaign.planned_inputs()
    campaign.save(HERE/'inputs.json',{name:dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)) for name,data in inputs.items()})
    print(json.dumps({'cases':len(campaign.cases()),'boundary_cases':len(campaign.rejections()),'artifacts':len(inputs)},sort_keys=True))


if __name__=='__main__':
    main()
