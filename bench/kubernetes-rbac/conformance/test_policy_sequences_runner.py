#!/usr/bin/env python3
"""Reject inconsistent or incomplete ordered native/production evidence."""
import copy
import json
import unittest
import run_policy_sequences as campaign
from test_policy_changes_runner import native_execution, model_execution
from test_coverage_runner import url_execution


def selected(name='grant-then-use'):
    return next(case for case in campaign.cases() if case['id']==name)


def native_sequence(case):
    states=campaign.states_for(case);steps=[]
    for index in range(len(case['expected']['steps'])):
        native=native_execution(campaign.single_case(case,index,states))['data']
        for entry in native['special']:
            if entry['decision']=='Allow':entry['granting_rule_indices']=[len(native['actor_rules'])-1]
        steps.append(dict(index=index+1,
            before_sha256=campaign.hashlib.sha256(campaign.native_state_bytes(case,states,index)).hexdigest(),
            after_sha256=campaign.hashlib.sha256(campaign.native_state_bytes(case,states,index+1)).hexdigest(),
            native=native))
    return dict(returncode=0,data=dict(schema_version=1,kind='rbac_policy_sequence_native',valid=True,validation_errors=[],
        accepted=case['expected']['accepted'],failed_step=case['expected']['failed_step'],state_count=len(states),states=states,steps=steps))


def production_sequence(case,native):
    expected=case['expected'];states=campaign.states_for(case)
    sources=[campaign.native_state_bytes(case,states,index) for index in range(len(states))]
    spec=case['contract']['requirements'];steps=[];prefixes=[]
    def report(result,property_name):
        return dict(schema_version=10,result=result,property=property_name,
            assurance=dict(profile=campaign.change.controller.PROFILE,status='within_profile',findings=[]),
            frozen_spec=dict(schema_version=10,kind=spec['kind'],canonical=json.dumps(spec)),counterexample=None,clause=None)
    for index,selected in enumerate(case['contract']['steps']):
        auth=None
        if index<len(native['data']['steps']):
            sub=campaign.single_case(case,index,states)
            auth=model_execution(sub,dict(data=native['data']['steps'][index]['native']))['data']['authorization']
        steps.append(dict(index=index+1,operation=selected['operation'],target=selected['target'],
            inputs=dict(before=campaign.identity(sources[index]),after=campaign.identity(sources[index+1])),authorization=auth))
    final=None
    if expected['accepted']:
        candidate=report('violated' if expected['result']=='contract_failed' else 'proved','kubernetes-rbac-access')
        comparison=copy.deepcopy(candidate) if candidate['result']=='violated' else report('violated' if expected['phase']=='final_verification' else 'proved','rbac-repair-preservation')
        final=dict(candidate_report=candidate,comparison_report=comparison)
    for index in range(1,len(states)-1):
        if expected['phase']=='complete':status='proved'
        elif expected['phase']=='intermediate_preservation':status='proved' if index<expected['failing_step'] else 'violated' if index==expected['failing_step'] else 'not_executed'
        else:status='not_executed'
        prefixes.append(dict(step=index,inputs=dict(before=campaign.identity(sources[0]),after=campaign.identity(sources[index])),
            status=status,report=None if status=='not_executed' else report(status,'rbac-sequence-preservation')))
    value=dict(schema_version=1,kind=campaign.KIND,result=expected['result'],reason='fixture sequence outcome',phase=expected['phase'],
        failing_step=expected['failing_step'],assurance=dict(profile=campaign.PROFILE,status='within_profile'),
        frozen_spec=dict(schema_version=1,kind=campaign.KIND,canonical=json.dumps(case['contract'])),
        inputs=campaign.change.input_identities(case),states=[dict(index=i,digest=campaign.identity(data)) for i,data in enumerate(sources)],
        steps=steps,verification=final,intermediate_preservation=prefixes)
    wanted=expected['witness']
    if wanted is not None:
        selected=prefixes[wanted['state']-1]['report'] if expected['phase']=='intermediate_preservation' else final['candidate_report' if expected['result']=='contract_failed' else 'comparison_report']
        origin=[] if wanted['after']=='NoOpinion' else ['RoleBinding/team-a/'+('leak-b -> ClusterRole/secret-reader' if wanted['kind']=='secrets' else 'new-binding -> ClusterRole/pods-reader')+'/rules/0']
        selected.update(counterexample=dict(principal=wanted['user'],identity_groups=next(i['groups'] for i in spec['context']['identities'] if i['username']==wanted['user']),
            action='get',object_request=dict(namespace='team-a',resource_kind=wanted['kind'],name='existing'),granting_rules=origin),
            clause=dict(name=wanted.get('failed','preservation-outside-change-scope'),kind='must_not_grant' if 'failed' in wanted else 'must_preserve'))
        if expected['result']=='contract_failed':final['comparison_report']=copy.deepcopy(selected)
    return dict(returncode=0 if expected['result']=='valid_sequence' else 3,data=value),sources


class SequenceConsumerTests(unittest.TestCase):
    def test_frozen_inventory(self):
        campaign.audit_pins(campaign.planned_inputs(),campaign.read_json(campaign.HERE/'inputs.json'))
        values=campaign.cases();self.assertGreaterEqual(len(values),40)
        self.assertEqual(len({c['id'] for c in values}),len(values))
        self.assertEqual(len(selected('sixteen-independent-writes')['contract']['steps']),16)
        overflow=next(c for c in campaign.rejections() if c['id']=='seventeen-steps')
        self.assertEqual(len(overflow['contract']['steps']),17)
        self.assertEqual(len({campaign.target_key(s['target']) for s in overflow['contract']['steps']}),17)
        for mutation in ['missing','extra','changed']:
            data=campaign.planned_inputs()
            if mutation=='missing':data.pop(next(iter(data)))
            elif mutation=='extra':data['invented']=b'{}'
            else:data[next(iter(data))]+=b' '
            with self.assertRaises(RuntimeError):campaign.audit_pins(data,campaign.read_json(campaign.HERE/'inputs.json'))

    def test_native_state_chain_and_execution_order(self):
        for name in ['grant-then-use','revoke-then-fail','future-authority-cannot-authorize-earlier','sixteen-independent-writes']:
            case=selected(name);good=native_sequence(case);campaign.audit_native(good,case)
            for mutation in ['index','hash','state','skipped','extra','accepted','failed-step','count','schema','exit']:
                execution=copy.deepcopy(good);value=execution['data']
                if mutation=='index':value['steps'][0]['index']=True
                elif mutation=='hash':value['steps'][0]['before_sha256']='0'*64
                elif mutation=='state':value['states'][1]['items'].pop()
                elif mutation=='skipped':value['steps'].pop()
                elif mutation=='extra':value['steps'].append(value['steps'][0])
                elif mutation=='accepted':value['accepted']=not value['accepted']
                elif mutation=='failed-step':value['failed_step']=True
                elif mutation=='count':value['state_count']=False
                elif mutation=='schema':value['schema_version']=True
                else:execution['returncode']=False
                with self.subTest(name=name,mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_native(execution,case)

    def test_reference_operands_come_from_preceding_state(self):
        case=selected('updated-reference-covered');good=native_sequence(case);campaign.audit_native(good,case)
        changed=copy.deepcopy(good)
        changed['data']['steps'][1]['native']['coverage'][0]['required_rules']=[]
        with self.assertRaises(RuntimeError):campaign.audit_native(changed,case)
        changed=copy.deepcopy(good)
        changed['data']['steps'][1]['native']['actor_rules']=[]
        with self.assertRaises(RuntimeError):campaign.audit_native(changed,case)

    def test_boundaries_cannot_execute_earlier_authorization(self):
        good=dict(returncode=1,data=dict(schema_version=1,kind='rbac_policy_sequence_native',valid=False,validation_errors=['unsupported'],
            accepted=False,failed_step=None,state_count=0,states=[],steps=[]))
        campaign.audit_native_boundary(good)
        for mutation in ['states','steps','accepted','errors','count']:
            value=copy.deepcopy(good)
            if mutation in ['states','steps']:value['data'][mutation]=[{}]
            elif mutation=='accepted':value['data']['accepted']=True
            elif mutation=='errors':value['data']['validation_errors']=[]
            else:value['data']['state_count']=False
            with self.assertRaises(RuntimeError):campaign.audit_native_boundary(value)

    def test_production_frozen_sequence_and_stage_coherence(self):
        for name in ['grant-then-use','revoke-then-fail','staged-in-scope-repair','final-access-failure','temporary-out-of-scope-loss','temporary-out-of-scope-gain','final-preservation-failure']:
            case=selected(name);native=native_sequence(case);good,sources=production_sequence(case,native)
            campaign.audit_production(good,case,native['data'],sources)
            for mutation in ['order','actor','scope','kind','exit','result','phase','failure','profile','inputs','state-digest','state-chain','step-target','authorization','prefix-status','prefix-baseline']:
                changed=copy.deepcopy(good);data=changed['data'];frozen=copy.deepcopy(case['contract'])
                if mutation=='order':frozen['steps'].reverse();data['frozen_spec']['canonical']=json.dumps(frozen)
                elif mutation=='actor':frozen['actor']='app';data['frozen_spec']['canonical']=json.dumps(frozen)
                elif mutation=='scope':frozen['requirements']['change_scope']=[campaign.change.controller.scope(resource='pods')];data['frozen_spec']['canonical']=json.dumps(frozen)
                elif mutation=='kind':data['kind']='kubernetes-rbac-policy-change'
                elif mutation=='exit':changed['returncode']=False
                elif mutation=='result':data['result']='unknown'
                elif mutation=='phase':data['phase']='preparation'
                elif mutation=='failure':data['failing_step']=True
                elif mutation=='profile':data['assurance']['status']='unsupported'
                elif mutation=='inputs':data['inputs']['after']['sha256']='0'*64
                elif mutation=='state-digest':data['states'][1]['digest']['bytes']=True
                elif mutation=='state-chain':data['steps'][0]['inputs']['after']=data['steps'][0]['inputs']['before']
                elif mutation=='step-target':data['steps'][0]['target']['name']='invented'
                elif mutation=='authorization':data['steps'][0]['authorization']['allowed']=False
                elif mutation=='prefix-status':data['intermediate_preservation'][0]['status']='invented'
                else:data['intermediate_preservation'][0]['inputs']['before']['sha256']='0'*64
                with self.subTest(name=name,mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_production(changed,case,native['data'],sources)
            changed=list(sources);changed[1]=campaign.encoded(case['before'])
            with self.assertRaises(RuntimeError):campaign.audit_production(good,case,native['data'],changed)

    def test_skipped_and_nested_reports_cannot_be_fabricated(self):
        case=selected('revoke-then-fail');native=native_sequence(case);good,sources=production_sequence(case,native)
        for mutation in ['final','prefix']:
            changed=copy.deepcopy(good)
            if mutation=='final':changed['data']['verification']={}
            else:changed['data']['intermediate_preservation'][0]['report']={}
            with self.assertRaises(RuntimeError):campaign.audit_production(changed,case,native['data'],sources)
        case=selected('temporary-out-of-scope-gain');native=native_sequence(case);good,sources=production_sequence(case,native)
        for mutation in ['candidate-result','candidate-identity','prefix-property','prefix-identity','prefix-result']:
            changed=copy.deepcopy(good);data=changed['data']
            if mutation=='candidate-result':data['verification']['candidate_report']['result']='violated'
            elif mutation=='candidate-identity':data['verification']['candidate_report']['frozen_spec']['canonical']='{}'
            elif mutation=='prefix-property':data['intermediate_preservation'][0]['report']['property']='rbac-repair-preservation'
            elif mutation=='prefix-identity':data['intermediate_preservation'][0]['report']['frozen_spec']['canonical']='{}'
            else:data['intermediate_preservation'][0]['report']['result']='proved'
            with self.assertRaises((RuntimeError,KeyError)):campaign.audit_production(changed,case,native['data'],sources)

    def test_witness_dimensions_scope_and_origins(self):
        for name in ['final-access-failure','temporary-out-of-scope-loss','temporary-out-of-scope-gain','final-preservation-failure']:
            case=selected(name);native=native_sequence(case);good,_=production_sequence(case,native)
            row=campaign.composition_witness(good['data'],case);self.assertEqual(row['username'],case['expected']['witness']['user'])
            for mutation in ['user','groups','kind','namespace','verb','clause','origin']:
                changed=copy.deepcopy(good['data']);expected=case['expected']
                report=changed['intermediate_preservation'][0]['report'] if expected['phase']=='intermediate_preservation' else changed['verification']['candidate_report' if expected['result']=='contract_failed' else 'comparison_report']
                witness=report['counterexample']
                if mutation=='user':witness['principal']='deployer'
                elif mutation=='groups':witness['identity_groups']=['invented']
                elif mutation=='kind':witness['object_request']['resource_kind']='configmaps'
                elif mutation=='namespace':witness['object_request']['namespace']='other'
                elif mutation=='verb':witness['action']='list'
                elif mutation=='clause':report['clause']['name']='invented'
                else:witness['granting_rules']=['invented origin']
                with self.subTest(name=name,mutation=mutation),self.assertRaises(RuntimeError):campaign.composition_witness(changed,case)

    def test_native_replay_uses_baseline_and_offending_state(self):
        for name in ['temporary-out-of-scope-loss','temporary-out-of-scope-gain','final-access-failure']:
            case=selected(name);native=native_sequence(case);good,_=production_sequence(case,native)
            row=campaign.composition_witness(good['data'],case);wanted=case['expected']['witness']
            before=url_execution([row],[wanted['before']]);after=url_execution([row],[wanted['after']])
            campaign.audit_witness_replay(before,after,row,wanted)
            changed=copy.deepcopy(after);changed['data']['decisions'][0]['decision']='NoOpinion' if wanted['after']=='Allow' else 'Allow'
            with self.assertRaises(RuntimeError):campaign.audit_witness_replay(before,changed,row,wanted)
            changed=copy.deepcopy(after);changed['data']['decisions'][0]['attributes']['username']='not-frozen'
            with self.assertRaises(RuntimeError):campaign.audit_witness_replay(before,changed,row,wanted)

    def test_completion_cannot_drop_cases_stages_or_witnesses(self):
        good=dict(failures=[],native_only=False,native_cases=41,native_boundaries=22,native_steps=69,model_cases=41,model_boundaries=22,
            witness_replays=4,witness_native_checks=8,native_linkage_verified=True,inputs_unchanged=True,binaries_unchanged=True,
            cases={c['id']:dict(accepted=c['expected']['accepted'],result=c['expected']['result']) for c in campaign.cases()})
        campaign.audit_completion(good)
        for mutation in ['cases','count','step-count','witness','checks','input','binary','linkage','mode']:
            changed=copy.deepcopy(good)
            if mutation=='cases':changed['cases'].pop(next(iter(changed['cases'])))
            elif mutation=='count':changed['model_cases']=True
            elif mutation=='step-count':changed['native_steps']-=1
            elif mutation=='witness':changed['witness_replays']=0
            elif mutation=='checks':changed['witness_native_checks']=4
            elif mutation=='input':changed['inputs_unchanged']=False
            elif mutation=='binary':changed['binaries_unchanged']=False
            elif mutation=='linkage':changed['native_linkage_verified']=False
            else:changed['native_only']=True
            with self.assertRaises(RuntimeError):campaign.audit_completion(changed)


if __name__=='__main__':unittest.main()
