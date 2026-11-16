#!/usr/bin/env python3
"""Adversarial retirement evidence tests; no native or production binary needed."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import run_policy_retirement as campaign
from test_policy_changes_runner import native_execution, model_execution
from test_coverage_runner import url_execution


def selected(name='replace-before-retire'):
    return next(item for item in campaign.cases() if item['id']==name)


def native(case):
    def single(index):
        sub=campaign.single_case(case,index)
        value=native_execution(sub)
        value['data']['initial']['attributes']=campaign.initial_attributes(sub)
        for special in value['data']['special']:
            if special['decision']=='Allow':special['granting_rule_indices']=[len(value['data']['actor_rules'])-1]
        return value
    if case['mode']=='change':return single(0)
    states=campaign.states_for(case);steps=[]
    for i in range(len(case['expected']['steps'])):
        steps.append(dict(index=i+1,before_sha256=campaign.hashlib.sha256(campaign.sequence.native_state_bytes(case,states,i)).hexdigest(),
            after_sha256=campaign.hashlib.sha256(campaign.sequence.native_state_bytes(case,states,i+1)).hexdigest(),native=single(i)['data']))
    return dict(returncode=0,data=dict(schema_version=1,kind='rbac_policy_sequence_native',valid=True,validation_errors=[],
        accepted=case['expected']['accepted'],failed_step=case['expected']['failed_step'],state_count=len(states),states=states,steps=steps))


def production(case,reference):
    expected=case['expected'];spec=case['contract'];nested=spec['requirements'];mode=case['mode']
    states=campaign.states_for(case);sources=[campaign.sequence.native_state_bytes(case,states,i) for i in range(len(states))]
    frozen=dict(schema_version=2,kind=spec['kind'],canonical=json.dumps(spec))
    def report(result,property_,outer=False):
        return dict(schema_version=10,result=result,property=property_,
            assurance=dict(profile=campaign.change.controller.PROFILE,status='within_profile',findings=[]),
            frozen_spec=copy.deepcopy(frozen) if outer else dict(schema_version=10,kind=nested['kind'],canonical=json.dumps(nested)),
            counterexample=None,clause=None)
    final=None
    if expected['accepted']:
        candidate=report('violated' if expected['result']=='contract_failed' else 'proved','kubernetes-rbac-access')
        comparison=copy.deepcopy(candidate) if candidate['result']=='violated' else report('violated' if expected['phase']=='final_verification' else 'proved','rbac-repair-preservation')
        final=dict(candidate_report=candidate,comparison_report=comparison)
    value=dict(schema_version=2,kind=spec['kind'],result=expected['result'],reason='fixture',
        assurance=dict(profile='kubernetes-rbac-v1.34-policy-'+('change' if mode=='change' else 'sequence')+'-v2',status='within_profile'),
        frozen_spec=frozen,inputs=campaign.change.input_identities(case),verification=final)
    if mode=='change':
        value['authorization']=model_execution(campaign.single_case(case,0),reference)['data']['authorization']
    else:
        steps=[];invariants=[];prefixes=[]
        for i,step in enumerate(campaign.steps_for(case)):
            auth=None
            if i<len(reference['data']['steps']):
                auth=model_execution(campaign.single_case(case,i),dict(data=reference['data']['steps'][i]['native']))['data']['authorization']
            steps.append(dict(index=i+1,operation=step['operation'],target=step['target'],
                inputs=dict(before=campaign.identity(sources[i]),after=campaign.identity(sources[i+1])),authorization=auth))
        for i in range(len(states) if spec['invariants'] else 0):
            if expected['phase'] in ['complete','intermediate_preservation']:status='proved'
            elif expected['phase']=='state_invariants':status='proved' if i<expected['failing_step'] else 'violated' if i==expected['failing_step'] else 'not_executed'
            else:status='not_executed'
            invariants.append(dict(state=i,input=campaign.identity(sources[i]),status=status,
                report=None if status=='not_executed' else report(status,'rbac-sequence-invariants',True)))
        for i in range(1,len(states)-1):
            if expected['phase']=='complete':status='proved'
            elif expected['phase']=='intermediate_preservation':status='proved' if i<expected['failing_step'] else 'violated' if i==expected['failing_step'] else 'not_executed'
            else:status='not_executed'
            prefixes.append(dict(step=i,inputs=dict(before=campaign.identity(sources[0]),after=campaign.identity(sources[i])),status=status,
                report=None if status=='not_executed' else report(status,'rbac-sequence-preservation')))
        value.update(phase=expected['phase'],failing_step=expected['failing_step'],steps=steps,state_invariants=invariants,
            intermediate_preservation=prefixes,states=[dict(index=i,digest=campaign.identity(data)) for i,data in enumerate(sources)])
    wanted=expected['witness']
    if wanted is not None:
        if expected['phase']=='state_invariants':failure=value['state_invariants'][wanted['state']]['report']
        elif expected['phase']=='intermediate_preservation':failure=value['intermediate_preservation'][wanted['state']-1]['report']
        else:failure=value['verification']['candidate_report' if expected['result']=='contract_failed' else 'comparison_report']
        name='existing' if wanted['kind']=='pods' else 'settings'
        clause=next((c for c in nested['clauses'] if c['name']==wanted.get('failed')),None)
        failure.update(clause=dict(name=wanted.get('failed','preservation-outside-change-scope'),kind=clause['kind'] if clause else 'must_preserve'),
            counterexample=dict(principal=wanted['user'],identity_groups=next(i['groups'] for i in nested['context']['identities'] if i['username']==wanted['user']),
                action=wanted['operation'],object_request=dict(namespace='team-a',resource_kind=wanted['kind'],name=name),granting_rules=wanted['origins']))
        if expected['result']=='contract_failed':value['verification']['comparison_report']=copy.deepcopy(failure)
    return dict(returncode=0 if expected['result'].startswith('valid_') else 3,data=value),sources


def evidence(folder,case,report,sources,executable):
    """Synthetic protocol fixture, not proof or native expectation generation."""
    folder.mkdir(mode=0o700)
    files={}
    def put(path,value):files[path]=campaign.encoded(value)
    put('contract.json',case['contract']);put('profile.json',{});put('report.json',report)
    spec=case['contract'];mode=case['mode']
    if report['verification'] is not None:
        final=report['verification'];put('verification/candidate-report.json',final['candidate_report']);put('verification/report.json',final['comparison_report'])
        put('verification/manifest.json',dict(schema_version=3,operation='repair_comparison',
            inputs={k:dict(sha256=v['sha256'],size_bytes=v['bytes']) for k,v in report['inputs'].items()},
            result=final['comparison_report']['result'],
            candidate_report=dict(path='candidate-report.json',sha256=campaign.hashlib.sha256(files['verification/candidate-report.json']).hexdigest()),
            report=dict(path='report.json',sha256=campaign.hashlib.sha256(files['verification/report.json']).hexdigest())))
    manifest=dict(schema_version=2,kind=spec['kind']+'-evidence',inputs=report['inputs'],authorization_method='deterministic-native-rbac-policy-coverage',
        provenance=dict(executable_sha256=campaign.digest(executable)),verification='not_executed' if report['verification'] is None else 'see verification/manifest.json')
    if mode=='sequence':
        for i,data in enumerate(sources):files['states/state-%03d.json'%i]=data
        prefixes=[]
        for entry in report['intermediate_preservation']:
            query='preservation/step-%03d.smt2'%entry['step'];files[query]=b'(check-sat)\n'
            path=None if entry['report'] is None else 'preservation/step-%03d-report.json'%entry['step']
            if path:put(path,entry['report'])
            prefixes.append(dict(step=entry['step'],status=entry['status'],query=query,report=path))
        planned=campaign.invariant_obligations(case);invariants=[]
        for entry in report['state_invariants']:
            index=entry['state'];prefix='invariants/state-%03d/'%index;status=entry['status']
            for q in planned:files[prefix+'queries/'+q['id']+'.smt2']=b'(check-sat)\n'
            manifest_path=None if status=='not_executed' else prefix+'manifest.json'
            invariants.append(dict(state=index,input=entry['input'],status=status,verification=manifest_path))
            if status=='not_executed':
                put(prefix+'plan.json',dict(state=index,input=entry['input'],status=status,
                    queries=[dict(id=q['id'],path='queries/'+q['id']+'.smt2') for q in planned]))
                continue
            put(prefix+'contract.json',spec);put(prefix+'report.json',entry['report']);obligations=[];decisive=False
            for q in planned:
                skipped=decisive;answer=None if skipped else 'sat' if q['phase']=='inhabitance' else 'unsat';model=None
                if not skipped and status=='violated' and q['phase']=='clause' and q['clauses']==[entry['report']['clause']['name']]:answer='sat';decisive=True
                if answer=='sat':
                    witness=entry['report']['counterexample'] if decisive else dict(principal='app',action='get',object_request=None)
                    model=dict(principal_name=witness['principal'],method=witness['action'],object_request=witness['object_request'])
                relative='queries/'+q['id']+'.smt2'
                obligations.append(dict(**q,query=dict(path=relative,sha256=campaign.hashlib.sha256(files[prefix+relative]).hexdigest()),
                    execution='not_executed' if skipped else 'executed',solver_result=answer,model=model,reason=None))
            put(manifest_path,dict(schema_version=2,result=status,config=dict(sha256=entry['input']['sha256'],size_bytes=entry['input']['bytes']),
                soundcheck=dict(executable_sha256=campaign.digest(executable)),obligation_plan=dict(status='complete',reason=None),obligations=obligations,
                contract=dict(path='contract.json',sha256=campaign.hashlib.sha256(files[prefix+'contract.json']).hexdigest()),
                report=dict(path='report.json',sha256=campaign.hashlib.sha256(files[prefix+'report.json']).hexdigest())))
        manifest.update(phase=report['phase'],failing_step=report['failing_step'],intermediate_preservation=prefixes,state_invariants=invariants)
    manifest['artifacts']=[dict(path=path,sha256=campaign.hashlib.sha256(data).hexdigest(),bytes=len(data)) for path,data in files.items()]
    for relative,data in files.items():
        path=folder/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o600)
    (folder/'manifest.json').write_bytes(campaign.encoded(manifest));(folder/'manifest.json').chmod(0o600)


def rewrite_artifact(folder,relative,mutate):
    path=folder/relative;value=campaign.read_json(path);mutate(value);path.write_bytes(campaign.encoded(value))
    top=campaign.read_json(folder/'manifest.json')
    for entry in top['artifacts']:
        if entry['path']==relative:entry.update(sha256=campaign.digest(path),bytes=path.stat().st_size)
    (folder/'manifest.json').write_bytes(campaign.encoded(top))


class RetirementConsumerTests(unittest.TestCase):
    def test_frozen_inventory(self):
        campaign.audit_pins(campaign.planned_inputs(),campaign.read_json(campaign.HERE/'inputs.json'))
        self.assertEqual(len(campaign.cases()),49);self.assertEqual(len(campaign.rejections()),29)
        self.assertEqual(len({c['id'] for c in campaign.cases()}),49)
        self.assertEqual(sum(len(c['expected']['steps']) for c in campaign.cases()),83)
        for mutation in ['missing','extra','changed']:
            inputs=campaign.planned_inputs()
            if mutation=='missing':inputs.pop(next(iter(inputs)))
            elif mutation=='extra':inputs['invented']=b'{}'
            else:inputs[next(iter(inputs))]+=b' '
            with self.assertRaises(RuntimeError):campaign.audit_pins(inputs,campaign.read_json(campaign.HERE/'inputs.json'))

    def test_native_delete_is_named_and_has_no_special_guard(self):
        for name in ['role-delete-named','clusterrolebinding-delete-special-only']:
            case=selected(name);good=native(case);campaign.audit_native(good,case)
            for mutation in ['verb','name','namespace','special','coverage','accepted','storage','actor','bool-index','schema']:
                changed=copy.deepcopy(good);value=changed['data']
                if mutation in ['verb','name','namespace']:value['initial']['attributes'][mutation]='invented'
                elif mutation=='special':value['special']=[value['initial']]
                elif mutation=='coverage':value['coverage']=[{}]
                elif mutation=='accepted':value['accepted']=not value['accepted']
                elif mutation=='storage':value['storage_calls']=True
                elif mutation=='actor':value['actor_rules']=[]
                elif mutation=='bool-index':value['initial']['granting_rule_indices']=[True]
                else:value['schema_version']=True
                with self.subTest(name=name,mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_native(changed,case)

    def test_native_sequence_states_and_authority_prefix(self):
        for name in ['replace-before-retire','delete-own-authority-then-fail','grant-delete-then-use']:
            case=selected(name);good=native(case);campaign.audit_native(good,case)
            for mutation in ['state','hash','count','step','failed','accepted']:
                changed=copy.deepcopy(good);value=changed['data']
                if mutation=='state':value['states'][1]['items'].pop()
                elif mutation=='hash':value['steps'][0]['after_sha256']='0'*64
                elif mutation=='count':value['state_count']=True
                elif mutation=='step':value['steps'].pop()
                elif mutation=='failed':value['failed_step']=True
                else:value['accepted']=not value['accepted']
                with self.assertRaises(RuntimeError):campaign.audit_native(changed,case)

    def test_schema2_frozen_identity_includes_invariants(self):
        case=selected();reference=native(case);good,sources=production(case,reference)
        campaign.audit_production(good,case,reference['data'],sources)
        for mutation in ['invariants','actor','order','scope','version','profile','target','inputs']:
            changed=copy.deepcopy(good);value=changed['data'];spec=copy.deepcopy(case['contract'])
            if mutation=='invariants':spec['invariants']=[]
            elif mutation=='actor':spec['actor']='app'
            elif mutation=='order':spec['steps'].reverse()
            elif mutation=='scope':spec['requirements']['change_scope']=[]
            elif mutation=='version':value['schema_version']=1
            elif mutation=='profile':value['assurance']['profile']='kubernetes-rbac-v1.34-policy-sequence-v1'
            elif mutation=='target':value['steps'][0]['target']['name']='changed'
            else:value['inputs']['before']['sha256']='0'*64
            value['frozen_spec']['canonical']=json.dumps(spec)
            with self.assertRaises(RuntimeError):campaign.audit_production(changed,case,reference['data'],sources)

    def test_baseline_and_post_state_invariants_cannot_be_skipped(self):
        for name in ['baseline-required-access-missing','retire-before-replacement-loses-invariant','temporary-in-scope-secret-grant','repair-goal-is-final-only']:
            case=selected(name);reference=native(case);good,sources=production(case,reference)
            campaign.audit_production(good,case,reference['data'],sources)
            for mutation in ['baseline','state','input','status','report','identity','property','failure']:
                changed=copy.deepcopy(good);value=changed['data'];entry=value['state_invariants'][0]
                executed=next(e for e in value['state_invariants'] if e['report'] is not None)
                if mutation=='baseline':value['state_invariants'].pop(0)
                elif mutation=='state':entry['state']=True
                elif mutation=='input':entry['input']['sha256']='0'*64
                elif mutation=='status':entry['status']='not_executed'
                elif mutation=='report':entry['report']=None
                elif mutation=='identity':executed['report']['frozen_spec']['canonical']='{}'
                elif mutation=='property':executed['report']['property']='kubernetes-rbac-access'
                else:value['failing_step']=True
                with self.subTest(name=name,mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_production(changed,case,reference['data'],sources)

    def test_stage_order_and_skipped_reports(self):
        for name in ['delete-own-authority-then-fail','delete-one-of-two-secret-grants','temporary-outside-scope-loss']:
            case=selected(name);reference=native(case);good,sources=production(case,reference)
            campaign.audit_production(good,case,reference['data'],sources)
            changed=copy.deepcopy(good);changed['data']['phase']='complete'
            with self.assertRaises(RuntimeError):campaign.audit_production(changed,case,reference['data'],sources)
        case=selected('delete-one-of-two-secret-grants');reference=native(case);good,sources=production(case,reference)
        changed=copy.deepcopy(good);changed['data']['state_invariants'][0]['report']={}
        with self.assertRaises(RuntimeError):campaign.audit_production(changed,case,reference['data'],sources)

    def test_negative_witnesses_bind_state_clause_and_native_replay(self):
        for case in campaign.cases():
            wanted=case['expected']['witness']
            if wanted is None:continue
            reference=native(case);good,_=production(case,reference);row=campaign.composition_witness(good['data'],case)
            before=url_execution([row],[wanted['before']]);after=url_execution([row],[wanted['after']])
            campaign.sequence.audit_witness_replay(before,after,row,wanted)
            changed=copy.deepcopy(after);changed['data']['decisions'][0]['decision']='NoOpinion' if wanted['after']=='Allow' else 'Allow'
            with self.assertRaises(RuntimeError):campaign.sequence.audit_witness_replay(before,changed,row,wanted)
            report=good['data']
            if case['expected']['phase']=='state_invariants':bad=report['state_invariants'][wanted['state']]['report']
            elif case['expected']['phase']=='intermediate_preservation':bad=report['intermediate_preservation'][wanted['state']-1]['report']
            else:bad=report['verification']['candidate_report' if case['expected']['result']=='contract_failed' else 'comparison_report']
            bad['counterexample']['granting_rules']=['invented origin']
            with self.assertRaises(RuntimeError):campaign.composition_witness(report,case)

    def test_evidence_trace_and_skipped_plans(self):
        for name in ['replace-before-retire','baseline-required-access-missing']:
            case=selected(name);reference=native(case);good,sources=production(case,reference)
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);executable=root/'binary';executable.write_bytes(b'fixture')
                for mutation in ['none','state-input','obligation-clause','query-hash','trace-after-failure','missing-final','skipped-plan','file-bytes']:
                    folder=root/mutation;evidence(folder,case,good['data'],sources,executable)
                    if mutation=='none':campaign.audit_evidence(folder,good['data'],case,executable);continue
                    if mutation=='state-input':
                        rewrite_artifact(folder,'invariants/state-000/manifest.json',lambda v:v['config'].update(sha256='0'*64))
                    elif mutation=='obligation-clause':
                        rewrite_artifact(folder,'invariants/state-000/manifest.json',lambda v:v['obligations'][0].update(clauses=['unselected']))
                    elif mutation=='query-hash':
                        rewrite_artifact(folder,'invariants/state-000/manifest.json',lambda v:v['obligations'][0]['query'].update(sha256='0'*64))
                    elif mutation=='trace-after-failure':
                        rewrite_artifact(folder,'invariants/state-000/manifest.json',lambda v:v['obligations'][-1].update(execution='not_executed',solver_result=None,model=None))
                    elif mutation=='missing-final':
                        (folder/'verification/manifest.json').unlink()
                    elif mutation=='skipped-plan':
                        if name=='replace-before-retire':
                            rewrite_artifact(folder,'invariants/state-000/manifest.json',lambda v:v.update(obligations=[]))
                        else:rewrite_artifact(folder,'invariants/state-001/plan.json',lambda v:v.update(queries=[]))
                    else:
                        (folder/'states/state-000.json').write_bytes(b'{}')
                    with self.subTest(name=name,mutation=mutation),self.assertRaises((RuntimeError,FileNotFoundError)):
                        campaign.audit_evidence(folder,good['data'],case,executable)

    def test_completion_requires_every_case_operation_state_and_witness(self):
        good=dict(failures=[],native_only=False,native_cases=49,native_boundaries=29,native_steps=83,native_state_checks=60,
            model_cases=49,model_boundaries=29,witness_replays=8,witness_native_checks=16,
            native_linkage_verified=True,inputs_unchanged=True,binaries_unchanged=True,
            cases={c['id']:dict(accepted=c['expected']['accepted'],result=c['expected']['result']) for c in campaign.cases()})
        campaign.audit_completion(good)
        for name in ['native_cases','native_steps','native_state_checks','model_boundaries','witness_replays','witness_native_checks']:
            changed=copy.deepcopy(good);changed[name]-=1
            with self.assertRaises(RuntimeError):campaign.audit_completion(changed)
        changed=copy.deepcopy(good);changed['cases'].pop(next(iter(changed['cases'])))
        with self.assertRaises(RuntimeError):campaign.audit_completion(changed)


if __name__=='__main__':unittest.main()
