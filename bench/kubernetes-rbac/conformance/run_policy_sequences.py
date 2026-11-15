#!/usr/bin/env python3
"""Frozen native ordered-write guards and per-prefix preservation acceptance."""
import argparse
import copy
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import digest, execute, module_provenance, read_json, require, save, strict_json
from run_resources import encoded, audit_pins
import run_policy_changes as change

HERE = Path(__file__).resolve().parent.parent / 'policy-sequences'
KIND = 'kubernetes-rbac-policy-sequence'
PROFILE = 'kubernetes-rbac-v1.34-policy-sequence-v1'
SOURCE_FILES = copy.deepcopy(change.SOURCE_FILES)
SOURCE_FILES['kubernetes'].append('pkg/controller/clusterroleaggregation/clusterroleaggregation_controller.go')
SOURCE_FILES['apimachinery'] = ['pkg/apis/meta/v1/helpers.go', 'pkg/labels/selector.go']
rule, role, binding, authority, snapshot = change.rule, change.role, change.binding, change.authority, change.snapshot


def key(obj):
    return obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name']


def target_key(target):
    return target['kind'], target['namespace'] or '', target['name']


def step(kind='Role', operation='create', name='target', namespace='team-a'):
    return dict(operation=operation, target=dict(kind=kind, name=name,
                namespace=namespace if kind in ['Role', 'RoleBinding'] else None))


def requirements(changes=()):
    value = change.controller.contract(changes=changes)
    value['context']['identities'] = copy.deepcopy(change.IDENTITIES)
    return value


def contract(steps, requirement=None):
    return dict(schema_version=1, kind=KIND, actor='deployer', steps=copy.deepcopy(steps),
                requirements=copy.deepcopy(requirement or requirements()))


def states_for(case):
    """Literal frozen object installation, never a permission decision."""
    final = {key(obj): obj for obj in case['after']['items']}
    states = [copy.deepcopy(case['before'])]
    for selected in case['contract']['steps']:
        state = copy.deepcopy(states[-1]); wanted = target_key(selected['target'])
        found = False
        for index, obj in enumerate(state['items']):
            if key(obj) == wanted:
                state['items'][index] = copy.deepcopy(final[wanted]); found = True
        if not found:
            state['items'].append(copy.deepcopy(final[wanted]))
        states.append(state)
    states[-1] = copy.deepcopy(case['after'])
    return states


def single_case(case, index, states=None):
    states = states or states_for(case)
    selected = case['contract']['steps'][index]
    spec = dict(schema_version=1, kind='kubernetes-rbac-policy-change', actor=case['contract']['actor'],
                operation=selected['operation'], target=selected['target'], requirements=case['contract']['requirements'])
    return dict(id=case['id']+'/'+str(index+1), before=states[index], after=states[index+1], contract=spec,
                expected=case['expected']['steps'][index])


def required_rules(subcase):
    obj = change.target_object(subcase)
    if not obj['kind'].endswith('Binding'):
        return copy.deepcopy(obj.get('rules') or [])
    ref = obj['roleRef']; namespace = obj['metadata'].get('namespace', '') if ref['kind'] == 'Role' else ''
    return copy.deepcopy(next(x.get('rules') or [] for x in subcase['before']['items']
        if key(x) == (ref['kind'], namespace, ref['name'])))


def case(id_, before, after, steps, decisions, result='valid_sequence', phase='complete', failing_step=None,
         requirement=None, witness=None):
    value = dict(id=id_, before=snapshot(before), after=snapshot(after), contract=contract(steps, requirement),
                 expected=dict(steps=[], result=result, phase=phase,
                    failing_step=len(steps) if phase=='final_verification' else failing_step, witness=witness))
    states = states_for(value)
    for index, decision in enumerate(decisions):
        initial, special, covered = decision[:3]
        value['expected']['steps'].append({})
        sub = single_case(value, index, states)
        operands = required_rules(sub) if initial and not special else []
        missing = copy.deepcopy(decision[3]) if len(decision) > 3 else ([] if covered is not False else change.atoms(operands))
        accepted = initial and bool(special or covered)
        value['expected']['steps'][index] = dict(initial='Allow' if initial else 'NoOpinion',
            special=None if not initial else ('Allow' if special else 'NoOpinion'), accepted=accepted,
            covered=covered, owner_rules=change.eligible_rules(sub) if covered is not None else [],
            required_rules=operands, missing_rules=missing, result='proved' if accepted else 'violated',
            stage='access' if accepted else 'authorization')
    failed = next((index+1 for index, entry in enumerate(value['expected']['steps']) if not entry['accepted']), None)
    value['expected'].update(accepted=failed is None, failed_step=failed)
    if failed is not None:
        value['expected'].update(result='authorization_failed', phase='authorization', failing_step=failed)
    return value


def cases():
    result = []
    # These one-step controls retain the independently frozen single-write
    # expected attributes/coverage and all four native storage wrappers.
    for original in change.cases():
        if any(original['id'] == kind.lower()+'-'+op+'-'+mode
               for kind in change.RESOURCES for op in ['create', 'update-existing']
               for mode in ['covered-future-policy', 'explicit-special', 'initial-not-granted']):
            spec = original['contract']; allowed = original['expected']['accepted']
            result.append(dict(id='single-'+original['id'], before=original['before'], after=original['after'],
                contract=contract([dict(operation=spec['operation'], target=spec['target'])], spec['requirements']),
                expected=dict(steps=[original['expected']], accepted=allowed, failed_step=None if allowed else 1,
                    result='valid_sequence' if allowed else 'authorization_failed',
                    phase='complete' if allowed else 'authorization', failing_step=None if allowed else 1, witness=None)))
    future = rule(['frobnicate'], ['future.example.test'], ['novelresources/arbitrary'], ['one'])
    old_future = rule(['oldverb'], ['future.example.test'], ['oldresources'], ['old'])
    policy = lambda verbs, resources, names=None: rule(verbs, [change.GROUP], resources, names)
    broad = authority([policy(['create', 'update', 'escalate', 'bind'], list(change.RESOURCES.values()))])
    common = change.common()
    role_steps = [step(name='new-role'), step('RoleBinding', name='new-binding')]
    role_new = role('Role', 'new-role', 'team-a', [future])
    binding_new = binding('RoleBinding', 'new-binding', 'team-a', 'Role', 'new-role')
    result.append(case('create-role-then-binding', common+broad, common+broad+[role_new,binding_new], role_steps,
                       [(True,True,None),(True,True,None)]))
    reordered = copy.deepcopy(result[-1]); reordered['id'] = 'candidate-list-order-independent'; reordered['after']['items'].reverse()
    result.append(reordered)

    initial = authority([policy(['update'], ['roles']), policy(['create'], ['rolebindings']), future])
    before = common+initial+[role('Role','new-role','team-a',[old_future])]
    after = common+initial+[role_new,binding_new]
    steps = [step(operation='update-existing',name='new-role'), step('RoleBinding',name='new-binding')]
    result.append(case('updated-reference-covered',before,after,steps,[(True,False,True),(True,False,True)]))
    result.append(case('old-reference-not-covered',before,after,list(reversed(steps)),[(True,False,False)]))

    future_authority = role('ClusterRole','future-authority',rules=[policy(['create','escalate'],['roles'])])
    base = common+authority([policy(['create','update'],['rolebindings']),policy(['bind'],['clusterroles'],['future-authority'])])+[future_authority]
    grant = binding('RoleBinding','self-grant','team-a',role_name='future-authority',subject='deployer')
    target = role('Role','later-role','team-a',[future])
    grant_steps = [step('RoleBinding',name='self-grant'),step(name='later-role')]
    result.append(case('grant-then-use',base,base+[grant,target],grant_steps,[(True,True,None),(True,True,None)]))
    result.append(case('future-authority-cannot-authorize-earlier',base,base+[grant,target],list(reversed(grant_steps)),[(False,None,None)]))
    revoked = copy.deepcopy(grant); revoked['subjects'][0]['name'] = 'former-recipient'
    revoke_steps = [step('RoleBinding','update-existing','self-grant'),step(name='later-role')]
    result.append(case('revoke-then-fail',base+[grant],base+[revoked,target],revoke_steps,[(True,True,None),(False,None,None)]))
    result.append(case('use-then-revoke',base+[grant],base+[revoked,target],list(reversed(revoke_steps)),[(True,True,None),(True,True,None)]))

    grant_rule = role('ClusterRole','future-policy',rules=[future])
    base = common+authority([policy(['create'],['rolebindings','roles']),policy(['bind'],['clusterroles'],['future-policy'])])+[grant_rule]
    grant = binding('RoleBinding','self-grant','team-a',role_name='future-policy',subject='deployer')
    result.append(case('grant-then-implicit-coverage',base,base+[grant,target],grant_steps,[(True,True,None),(True,False,True)]))

    initial = authority([policy(['update','escalate'],['roles']),policy(['create'],['rolebindings']),old_future])
    before = common+initial+[role('Role','new-role','team-a',[old_future])]
    after = common+initial+[role_new,binding_new]
    result.append(case('updated-reference-requires-new-coverage',before,after,steps,[(True,True,None),(True,False,False)]))
    own = role('Role','own-authority','team-a',[policy(['update'],['roles'])])
    own_binding = binding('RoleBinding','own-binding','team-a','Role','own-authority','deployer')
    expanded = copy.deepcopy(own); expanded['rules'].append(policy(['escalate'],['roles']))
    result.append(case('self-escalation-first-write',common+[own,own_binding],common+[expanded,own_binding,target],
        [step(operation='update-existing',name='own-authority'),step(name='later-role')],[(True,False,False,[policy(['escalate'],['roles'])])]))

    many = [role('Role','target-'+str(index),'team-a',[future]) for index in range(16)]
    result.append(case('sixteen-independent-writes',common+broad,common+broad+many,
        [step(name='target-'+str(index)) for index in range(16)],[(True,True,None)]*16))

    # A scoped repair spans two bindings. Both carry the prohibited grant at
    # S0, so the first prefix may still violate final access requirements.
    secret_role = role('ClusterRole','secret-reader',rules=[rule(resources=['secrets'])])
    leak_a = binding('RoleBinding','leak-a','team-a',role_name='secret-reader',subject='app')
    leak_b = binding('RoleBinding','leak-b','team-a',role_name='secret-reader',subject='app')
    fixed_a = copy.deepcopy(leak_a); fixed_a['subjects'] = []
    fixed_b = copy.deepcopy(leak_b); fixed_b['subjects'] = []
    repair_spec = requirements([change.controller.scope(resource='secrets')])
    base = common+broad+[secret_role]
    repair_steps = [step('RoleBinding','update-existing','leak-a'),step('RoleBinding','update-existing','leak-b')]
    result.append(case('staged-in-scope-repair',base+[leak_a,leak_b],base+[fixed_a,fixed_b],repair_steps,
        [(True,True,None),(True,True,None)],requirement=repair_spec))
    partial = copy.deepcopy(leak_b); partial['subjects'].append(dict(apiGroup=change.GROUP,kind='User',name='other'))
    result.append(case('final-access-failure',base+[leak_a,leak_b],base+[fixed_a,partial],repair_steps,
        [(True,True,None),(True,True,None)],result='contract_failed',phase='final_verification',requirement=repair_spec,
        witness=dict(state=2,kind='secrets',operation='get',user='app',before='Allow',after='Allow',failed='forbidden-secrets')))

    # Distinct final objects can still create transient effective grants or
    # outages. The final aggregate decision equals S0 in these two cases.
    pods = role('ClusterRole','pods-reader',rules=[rule(resources=['pods'],names=['existing'])])
    old = binding('RoleBinding','old-binding','team-a',role_name='pods-reader',subject='ops')
    empty = copy.deepcopy(old); empty['subjects'] = []
    new = binding('RoleBinding','new-binding','team-a',role_name='pods-reader',subject='ops')
    base = common+broad+[pods]
    loss_steps = [step('RoleBinding','update-existing','old-binding'),step('RoleBinding',name='new-binding')]
    result.append(case('temporary-out-of-scope-loss',base+[old],base+[empty,new],loss_steps,[(True,True,None)]*2,
        result='out_of_scope_regression',phase='intermediate_preservation',failing_step=1,
        witness=dict(state=1,kind='pods',operation='get',user='ops',before='Allow',after='NoOpinion')))
    empty_role = copy.deepcopy(pods); empty_role['rules'] = []
    gain_steps = [step('RoleBinding',name='new-binding'),step('ClusterRole','update-existing','pods-reader')]
    result.append(case('temporary-out-of-scope-gain',base,common+broad+[empty_role,new],gain_steps,[(True,True,None)]*2,
        result='out_of_scope_regression',phase='intermediate_preservation',failing_step=1,
        witness=dict(state=1,kind='pods',operation='get',user='ops',before='NoOpinion',after='Allow')))
    result.append(case('final-preservation-failure',base,base+[new,role('Role','second','team-a',[future])],
        [step('RoleBinding',name='new-binding'),step(name='second')],[(True,True,None)]*2,
        result='out_of_scope_regression',phase='final_verification',
        witness=dict(state=2,kind='pods',operation='get',user='ops',before='NoOpinion',after='Allow')))
    return result


def rejections():
    result = []
    source = next(c for c in cases() if c['id']=='create-role-then-binding')
    for name in ['zero-steps','seventeen-steps','duplicate-target','reversed-reference','extra-object','removed-object',
                 'other-metadata','step-no-op','missing-final-target','create-existing','patch','delete','actor','masters',
                 'extra-step-field','missing-namespace','unknown-version','unresolved-final-binding','late-invalid-before-authorization']:
        value=copy.deepcopy(source);value['id']=name;spec=value['contract'];before=value['before']['items'];after=value['after']['items']
        if name=='zero-steps':spec['steps']=[]
        elif name=='seventeen-steps':
            for index in range(15):
                name_='overflow-'+str(index)
                spec['steps'].append(step(name=name_))
                after.append(role('Role',name_,'team-a',[rule()]))
        elif name=='duplicate-target':spec['steps'].append(copy.deepcopy(spec['steps'][0]))
        elif name=='reversed-reference':spec['steps'].reverse()
        elif name=='extra-object':after.append(role('Role','unapproved','team-a'))
        elif name=='removed-object':after.pop(0)
        elif name=='other-metadata':after[0]['metadata']['annotations']={'changed':'true'}
        elif name=='step-no-op':
            before.append(copy.deepcopy(after[-2]));spec['steps'][0]['operation']='update-existing'
        elif name=='missing-final-target':after.pop(-2)
        elif name=='create-existing':before.append(copy.deepcopy(after[-2]))
        elif name in ['patch','delete']:spec['steps'][0]['operation']=name
        elif name=='actor':spec['actor']='not-frozen'
        elif name=='masters':spec['requirements']['context']['identities'][-1]['groups'].append('system:masters')
        elif name=='extra-step-field':spec['steps'][0]['actor']='app'
        elif name=='missing-namespace':spec['steps'][0]['target'].pop('namespace')
        elif name=='unknown-version':spec['schema_version']=2
        elif name=='unresolved-final-binding':after[-1]['roleRef']['name']='missing'
        else:
            before[2]['rules']=[];after[2]['rules']=[]
            # Keep S0 complete and the first write supported but ungranted.
            # A later independent no-op must still win as whole-plan unknown.
            existing=role('Role','later-noop','team-a',[rule()])
            before.append(copy.deepcopy(existing));after[-1]=copy.deepcopy(existing)
            spec['steps'][1]=step('Role','update-existing','later-noop')
        result.append(value)
    source=next(c for c in cases() if c['id']=='revoke-then-fail')
    for name in ['changed-role-ref','aggregate-target']:
        value=copy.deepcopy(source);value['id']=name
        if name=='changed-role-ref':value['after']['items'][-2]['roleRef']['name']='actor-authority'
        else:
            selected=step('ClusterRole','update-existing','future-authority');value['contract']['steps'][0]=selected
            for state in ['before','after']:
                obj=next(x for x in value[state]['items'] if key(x)==('ClusterRole','','future-authority'))
                obj['aggregationRule']={'clusterRoleSelectors':[{'matchLabels':{'missing':'yes'}}]};obj['rules']=[]
            value['after']['items'][-2]=copy.deepcopy(value['before']['items'][-1])
        result.append(value)
    # Both endpoints are fixed points: replacing contributor labels/rules in
    # separate writes creates an unsupported stale aggregate only at S1.
    base=change.common()+authority([rule(['update','escalate'],[change.GROUP],['clusterroles'])])
    first=role('ClusterRole','contributor-a',rules=[rule(resources=['pods'])]);first['metadata']['labels']={'part':'yes'}
    second=role('ClusterRole','contributor-b',rules=[rule(resources=['pods'])])
    agg=role('ClusterRole','aggregate',rules=[rule(resources=['pods'])]);agg['aggregationRule']={'clusterRoleSelectors':[{'matchLabels':{'part':'yes'}}]}
    next_first=copy.deepcopy(first);next_first['rules']=[];next_first['metadata']['labels']={}
    next_second=copy.deepcopy(second);next_second['rules'].append(rule(resources=['pods']));next_second['metadata']['labels']={'part':'yes'}
    result.append(dict(id='stale-intermediate-aggregate',before=snapshot(base+[first,second,agg]),after=snapshot(base+[next_first,next_second,agg]),
        contract=contract([step('ClusterRole','update-existing','contributor-a'),step('ClusterRole','update-existing','contributor-b')])))
    return result


def planned_inputs():
    output={'source-inventory.json':encoded(SOURCE_FILES),'native-linkage.json':encoded(change.LINKAGE)}
    for item in cases():
        for name in ['before','after','contract','expected']:
            output[item['id']+'/'+name+'.json']=encoded(item[name])
    for item in rejections():
        for name in ['before','after','contract']:
            output['rejections/'+item['id']+'/'+name+'.json']=encoded(item[name])
    return output


def normalized_snapshot(value):
    return sorted(value['items'],key=key)


def native_state_bytes(case,states,index):
    if index==0:return encoded(case['before'])
    if index==len(states)-1:return encoded(case['after'])
    return json.dumps(states[index],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def audit_native(execution,case):
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native sequence command failed')
    value=execution.get('data');expected=case['expected'];states=states_for(case)
    fields={'schema_version','kind','valid','validation_errors','accepted','failed_step','state_count','states','steps'}
    require(isinstance(value,dict) and set(value)==fields,'Wrong native sequence shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_policy_sequence_native', 'Wrong native sequence identity')
    require(value['valid'] is True and value['validation_errors']==[] and type(value['accepted']) is bool and value['accepted'] is expected['accepted'],'Wrong native sequence outcome')
    require(type(value['state_count']) is int and value['state_count']==len(states) and isinstance(value['states'],list) and len(value['states'])==len(states),'Wrong native state inventory')
    require(encoded(value['states'])==encoded(states),'Native independently derived snapshots differ')
    require(value['failed_step'] is None if expected['failed_step'] is None else type(value['failed_step']) is int and value['failed_step']==expected['failed_step'],'Wrong native failing step')
    require(isinstance(value['steps'],list) and len(value['steps'])==len(expected['steps']),'Wrong native executed step count')
    for index,entry in enumerate(value['steps']):
        require(isinstance(entry,dict) and set(entry)=={'index','before_sha256','after_sha256','native'} and type(entry['index']) is int and entry['index']==index+1,'Wrong native step identity')
        for field,state in [('before_sha256',index),('after_sha256',index+1)]:
            require(entry[field]==hashlib.sha256(native_state_bytes(case,states,state)).hexdigest(),'Native state digest differs')
        change.audit_native(dict(returncode=0,data=entry['native']),single_case(case,index,states))
    return value


def audit_native_boundary(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==1,'Native sequence accepted boundary')
    value=execution.get('data')
    require(isinstance(value,dict) and type(value.get('schema_version')) is int and value['schema_version']==1 and value.get('kind')=='rbac_policy_sequence_native','Wrong native boundary identity')
    require(value.get('valid') is False and value.get('accepted') is False and value.get('steps')==[] and value.get('states')==[]
            and type(value.get('state_count')) is int and value['state_count']==0 and value.get('failed_step') is None,'Structural boundary reached native guards')
    require(isinstance(value.get('validation_errors'),list) and value['validation_errors'] and all(isinstance(x,str) and x for x in value['validation_errors']),'Missing native boundary reason')


def normalized_contract(value):
    result=copy.deepcopy(value)
    result['requirements']=change.controller.coverage.normalized_contract(result['requirements'])
    return result


def identity(data):
    return dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))


def audit_nested(report,spec,wanted,property_name):
    # The existing frozen report validator knows two property names. Validate
    # the actual prefix name first, then reuse its unchanged field/identity
    # checks. No report is changed on disk or supplied to verification.
    require(isinstance(report,dict) and report.get('property')==property_name,'Wrong nested obligation property')
    comparison=property_name!='kubernetes-rbac-access'
    normalized=dict(report)
    if property_name=='rbac-sequence-preservation':normalized['property']='rbac-repair-preservation'
    change.controller.audit_report(dict(returncode=change.controller.EXIT_CODES[wanted],data=normalized),spec,wanted,comparison)


def audit_production(execution,case,native,state_sources):
    expected=case['expected'];value=execution.get('data');steps=case['contract']['steps'];states=states_for(case)
    fields={'schema_version','kind','result','reason','phase','failing_step','assurance','frozen_spec','inputs','states','steps','verification','intermediate_preservation'}
    require(type(execution.get('returncode')) is int and execution['returncode']==(0 if expected['result']=='valid_sequence' else 3),'Wrong production sequence exit')
    require(isinstance(value,dict) and set(value)==fields and type(value['schema_version']) is int and value['schema_version']==1 and value['kind']==KIND,'Wrong production sequence shape/identity')
    require(value['result']==expected['result'] and value['phase']==expected['phase'] and isinstance(value['reason'],str) and value['reason'],'Wrong composite outcome/phase')
    require(value['failing_step'] is None if expected['failing_step'] is None else type(value['failing_step']) is int and value['failing_step']==expected['failing_step'],'Wrong composite failing step')
    require(value['assurance']==dict(profile=PROFILE,status='within_profile'),'Wrong sequence assurance')
    frozen=value['frozen_spec']
    require(isinstance(frozen,dict) and set(frozen)=={'schema_version','kind','canonical'} and type(frozen['schema_version']) is int and frozen['schema_version']==1 and frozen['kind']==KIND and isinstance(frozen['canonical'],str),'Missing frozen sequence identity')
    require(encoded(normalized_contract(strict_json(frozen['canonical'])))==encoded(normalized_contract(case['contract'])),'Frozen actor/order/targets/requirements changed')
    require(encoded(value['inputs'])==encoded(change.input_identities(case)),'Sequence exact endpoint inputs changed')
    require(len(state_sources)==len(states),'Missing independently checked evidence states')
    for index,data in enumerate(state_sources):
        require(encoded(strict_json(data.decode()))==encoded(states[index]),'Production state differs from independent installation plan')
    require(state_sources[0]==encoded(case['before']) and state_sources[-1]==encoded(case['after']),'Evidence endpoints do not retain exact input bytes')
    wanted_states=[dict(index=index,digest=identity(data)) for index,data in enumerate(state_sources)]
    require(encoded(value['states'])==encoded(wanted_states),'State inventory/digests changed')
    require(isinstance(value['steps'],list) and len(value['steps'])==len(steps),'Missing declared step reports')
    for index,(entry,selected) in enumerate(zip(value['steps'],steps)):
        require(isinstance(entry,dict) and set(entry)=={'index','operation','target','inputs','authorization'} and type(entry['index']) is int and entry['index']==index+1,'Wrong production step shape/index')
        require(entry['operation']==selected['operation'] and encoded(entry['target'])==encoded(selected['target']),'Frozen operation/target changed')
        require(encoded(entry['inputs'])==encoded(dict(before=identity(state_sources[index]),after=identity(state_sources[index+1]))),'Step input chain mismatch')
        if index<len(native['steps']):
            sub=single_case(case,index,states)
            change.audit_model(dict(returncode=0,data=dict(result='authorization_allowed' if sub['expected']['accepted'] else 'authorization_failed',
                authorization=entry['authorization'],reason='')),sub,native['steps'][index]['native'])
        else:require(entry['authorization'] is None,'Authorization ran beyond first failure')
    final=value['verification'];spec=case['contract']['requirements']
    if not expected['accepted']:
        require(final is None,'Final verifier ran after native authorization failure')
    else:
        require(isinstance(final,dict) and set(final)=={'comparison_report','candidate_report'},'Missing final comparison')
        candidate='violated' if expected['result']=='contract_failed' else 'proved'
        comparison='violated' if expected['phase']=='final_verification' else 'proved'
        audit_nested(final['candidate_report'],spec,candidate,'kubernetes-rbac-access')
        audit_nested(final['comparison_report'],spec,comparison,'kubernetes-rbac-access' if candidate=='violated' else 'rbac-repair-preservation')
        if candidate=='violated':require(encoded(final['candidate_report'])==encoded(final['comparison_report']),'Failed candidate was replaced by preservation verdict')
    prefixes=value['intermediate_preservation']
    require(isinstance(prefixes,list) and len(prefixes)==len(steps)-1,'Missing prefix obligations')
    for index,entry in enumerate(prefixes,1):
        require(isinstance(entry,dict) and set(entry)=={'step','inputs','status','report'} and type(entry['step']) is int and entry['step']==index,'Wrong prefix obligation identity')
        require(encoded(entry['inputs'])==encoded(dict(before=identity(state_sources[0]),after=identity(state_sources[index]))),'Prefix preservation used wrong baseline/state')
        if expected['phase']=='complete':status='proved'
        elif expected['phase']=='intermediate_preservation':
            status='proved' if index<expected['failing_step'] else 'violated' if index==expected['failing_step'] else 'not_executed'
        else:status='not_executed'
        require(entry['status']==status,'Wrong prefix execution status')
        if status=='not_executed':require(entry['report'] is None,'Skipped prefix carries a report')
        else:audit_nested(entry['report'],spec,status,'rbac-sequence-preservation')
    return value


def audit_production_boundary(execution):
    value=execution.get('data')
    require(type(execution.get('returncode')) is int and execution['returncode']==4,'Boundary did not exit unknown')
    require(isinstance(value,dict) and type(value.get('schema_version')) is int and value['schema_version']==1 and value.get('kind')==KIND,'Wrong production boundary identity')
    require(value.get('result')=='unknown' and value.get('phase')=='preparation' and value.get('states')==[] and value.get('steps')==[]
        and value.get('verification') is None and value.get('intermediate_preservation')==[],'Whole-plan boundary reached a later stage')
    require(value.get('assurance')==dict(profile=PROFILE,status='unsupported_or_inconclusive') and isinstance(value.get('reason'),str) and value['reason'],'Boundary lost assurance/diagnostic')


def audit_evidence(directory,report,case,executable):
    manifest=read_json(directory/'manifest.json')
    require(type(manifest.get('schema_version')) is int and manifest['schema_version']==1 and manifest.get('kind')=='kubernetes-rbac-policy-sequence-evidence','Wrong evidence kind')
    require(encoded(manifest.get('inputs'))==encoded(report['inputs']) and manifest.get('phase')==report['phase'] and encoded(manifest.get('failing_step'))==encoded(report['failing_step']),'Evidence outcome/input mismatch')
    require(manifest.get('authorization_method')=='deterministic-native-rbac-policy-coverage','Evidence conflated authorization with SMT')
    require(manifest.get('provenance',{}).get('executable_sha256')==digest(executable),'Evidence executable identity differs')
    artifacts=manifest.get('artifacts');require(isinstance(artifacts,list) and artifacts,'Missing evidence artifact inventory')
    seen=set()
    for artifact in artifacts:
        require(isinstance(artifact,dict) and set(artifact)=={'path','sha256','bytes'} and isinstance(artifact['path'],str),'Bad evidence artifact')
        relative=Path(artifact['path'])
        require(not relative.is_absolute() and '..' not in relative.parts and artifact['path'] not in seen,'Unsafe/duplicate evidence artifact')
        seen.add(artifact['path']);path=directory/relative
        require(path.is_file() and not path.is_symlink() and type(artifact['bytes']) is int and artifact['bytes']==path.stat().st_size and artifact['sha256']==digest(path),'Evidence artifact digest differs')
    actual={str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
    require(actual==seen|{'manifest.json'},'Evidence files differ from manifest inventory')
    require(encoded(read_json(directory/'report.json'))==encoded(report),'Evidence report differs from single execution')
    require(encoded(normalized_contract(read_json(directory/'contract.json')))==encoded(normalized_contract(case['contract'])),'Evidence frozen contract differs')
    states=[(directory/('states/state-%03d.json'%index)).read_bytes() for index in range(len(case['contract']['steps'])+1)]
    wanted=[]
    for entry in report['intermediate_preservation']:
        index=entry['step'];query='preservation/step-%03d.smt2'%index
        require(query in seen and (directory/query).stat().st_size>0,'Missing planned prefix query')
        path=None if entry['report'] is None else 'preservation/step-%03d-report.json'%index
        if path is not None:require(encoded(read_json(directory/path))==encoded(entry['report']),'Prefix evidence report differs')
        wanted.append(dict(step=index,status=entry['status'],query=query,report=path))
    require(encoded(manifest.get('intermediate_preservation'))==encoded(wanted),'Prefix evidence plan differs')
    require(manifest.get('verification')==('not_executed' if report['verification'] is None else 'see verification/manifest.json'),'Final evidence stage differs')
    return states


def composition_witness(report,case):
    wanted=case['expected']['witness']
    if wanted is None:return None
    if case['expected']['phase']=='intermediate_preservation':
        selected=report['intermediate_preservation'][wanted['state']-1]['report']
    else:
        selected=report['verification']['candidate_report' if case['expected']['result']=='contract_failed' else 'comparison_report']
    witness=selected.get('counterexample');require(isinstance(witness,dict),'Missing sequence witness')
    obj=witness.get('object_request');require(isinstance(obj,dict) and set(obj)=={'namespace','name','resource_kind'},'Missing typed witness coordinates')
    require(obj['resource_kind']==wanted['kind'] and witness.get('principal')==wanted['user'] and witness.get('action')==wanted['operation'],'Wrong witness obligation dimensions')
    group,resource,subresource,_=change.controller.KINDS[obj['resource_kind']]
    row=dict(id='witness',username=witness['principal'],groups=witness.get('identity_groups'),operation=witness['action'],
        apiGroup=group,resource=resource,subresource=subresource,namespace=obj['namespace'],name=obj['name'],resourceRequest=True)
    spec=case['contract']['requirements'];identities={i['username']:i['groups'] for i in spec['context']['identities']}
    change.controller.validate_request(row,identities,spec['custom_resources'])
    origins=witness.get('granting_rules')
    require(isinstance(origins,list) and all(isinstance(origin,str) and origin for origin in origins) and len(origins)==len(set(origins)),'Malformed witness grant origins')
    require(bool(origins)==(wanted['after']=='Allow'),'Witness grant origins disagree with post-state decision')
    clause=selected.get('clause');require(isinstance(clause,dict),'Missing witness clause')
    if 'failed' in wanted:
        clauses=[c for c in spec['clauses'] if c['name']==wanted['failed']]
        require(len(clauses)==1 and clause.get('name')==wanted['failed'] and clause.get('kind')==clauses[0]['kind'] and change.controller.scope_matches(clauses[0],row),'Witness outside failed final clause')
    else:
        require(clause.get('name')=='preservation-outside-change-scope' and clause.get('kind')=='must_preserve' and not any(change.controller.scope_matches(scope,row) for scope in spec['change_scope']),'Witness not outside frozen scope')
        require(obj['namespace']=='team-a' and obj['name']=='existing','Witness outside independently introduced permission')
    expected_origins={
        'final-access-failure':['RoleBinding/team-a/leak-b -> ClusterRole/secret-reader/rules/0'],
        'temporary-out-of-scope-loss':[],
        'temporary-out-of-scope-gain':['RoleBinding/team-a/new-binding -> ClusterRole/pods-reader/rules/0'],
        'final-preservation-failure':['RoleBinding/team-a/new-binding -> ClusterRole/pods-reader/rules/0']}
    require(origins==expected_origins[case['id']],'Witness granting origin differs from frozen introduced/retained binding')
    return row


def audit_witness_replay(before,after,row,wanted):
    old=change.controller.coverage.audit_native_urls(before,[row])['witness']
    new=change.controller.coverage.audit_native_urls(after,[row])['witness']
    require(old==wanted['before'] and new==wanted['after'],'Native witness did not establish frozen obligation')


def replay_witness(reference,folder,row,case,environment):
    wanted=case['expected']['witness'];states=states_for(case)
    # Replay on independent frozen snapshots, never on production-emitted states.
    path=folder/'witness-urls.json';save(path,[change.controller.as_url(row)])
    old=folder/'witness-baseline.json';new=folder/'witness-state.json';save(old,states[0]);save(new,states[wanted['state']])
    before=execute([reference,'--coverage-urls',old,path],folder/'witness-before-native.json',environment)
    after=execute([reference,'--coverage-urls',new,path],folder/'witness-after-native.json',environment)
    audit_witness_replay(before,after,row,wanted)
    return [path,old,new]


def audit_completion(result,native_only=False):
    require(result.get('failures')==[] and result.get('native_only') is native_only,'Completion failure/mode mismatch')
    witnesses=sum(case['expected']['witness'] is not None for case in cases())
    counts=dict(native_cases=len(cases()),native_boundaries=len(rejections()),native_steps=sum(len(c['expected']['steps']) for c in cases()),
        model_cases=0 if native_only else len(cases()),model_boundaries=0 if native_only else len(rejections()),
        witness_replays=0 if native_only else witnesses,witness_native_checks=0 if native_only else 2*witnesses)
    for name,want in counts.items():require(type(result.get(name)) is int and result[name]==want,'Missing completion counter '+name)
    expected={case['id']:dict(accepted=case['expected']['accepted']) for case in cases()}
    if not native_only:
        for case in cases():expected[case['id']]['result']=case['expected']['result']
    require(encoded(result.get('cases'))==encoded(expected),'Incomplete case receipt')
    for name in ['native_linkage_verified','inputs_unchanged','binaries_unchanged']:require(result.get(name) is True,'Missing provenance '+name)


def source_provenance(metadata_file):
    metadata=read_json(metadata_file);root=Path(metadata['Dir']).parent;pins=read_json(HERE/'source-pins.json');result={}
    require(set(pins)==set(SOURCE_FILES),'Wrong pinned module inventory')
    for module,files in SOURCE_FILES.items():
        require(set(pins[module])==set(files),'Wrong pinned source inventory')
        for name in files:
            path=root/(module+'@'+('v1.34.0' if module=='kubernetes' else 'v0.34.0'))/name
            require(digest(path)==pins[module][name],'Changed upstream source '+str(path));result[str(path)]=pins[module][name]
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['reference','module-metadata','output']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--soundcheck',type=Path);parser.add_argument('--z3',default='z3');parser.add_argument('--native-only',action='store_true')
    args=parser.parse_args(argv)
    result=dict(schema_version=1,kind='rbac_policy_sequence_conformance',complete=False,native_only=args.native_only,
        native_cases=0,native_boundaries=0,native_steps=0,model_cases=0,model_boundaries=0,witness_replays=0,witness_native_checks=0,
        cases={},failures=[],input_sha256={},source_sha256={},binary_sha256={},upstream_source_sha256={},
        limitations=['Finite synthetic conditional sequence checks are not live deployment evidence or a universal correctness proof.',
            'Fixture storage assumes successful visible writes without interleaving; no concurrency, admission or runtime effects are modeled.'])
    save(args.output,result)
    try:
        require(args.native_only or args.soundcheck is not None,'Production comparison requires --soundcheck')
        result['reference']=module_provenance(args.module_metadata);result['upstream_source_sha256']=source_provenance(args.module_metadata)
        inputs=planned_inputs();audit_pins(inputs,read_json(HERE/'inputs.json'))
        # Evidence destinations are create-only. Keep each invocation's sealed
        # bundles in a fresh directory so rerunning the combined harness never
        # overwrites an earlier bundle or fails merely because it exists.
        artifacts=Path(tempfile.mkdtemp(prefix='artifacts-',dir=args.output.parent))
        for name,data in inputs.items():
            path=artifacts/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);result['input_sha256'][str(path)]=digest(path)
        source=Path(__file__).resolve().parent
        paths=[HERE/'inputs.json',HERE/'source-pins.json',HERE/'generate.py',HERE/'README.md',source/'run.sh',source/'test_policy_sequences_runner.py',args.module_metadata]
        paths+=sorted(source.glob('run*.py'))+sorted((source/'oracle').glob('*.go'))+[source/'oracle/go.mod',source/'oracle/go.sum',source/'oracle/module-pins.json']
        result['source_sha256']={str(path):digest(path) for path in paths};binaries=[args.reference]
        if not args.native_only:
            solver=shutil.which(args.z3);require(solver is not None,'Z3 unavailable');solver=Path(solver).resolve();binaries+=[args.soundcheck,solver]
        result['binary_sha256']={str(path):digest(path) for path in binaries};save(args.output.parent/'before-execution.json',result)
        change.audit_linkage(execute([args.reference,'--policy-change-reference-info'],args.output.parent/'native-linkage.json',dict(os.environ)))
        result['native_linkage_verified']=True
        environment=dict(os.environ)
        if not args.native_only:
            # The CLI uses its normal z3 lookup; resolve the explicitly selected
            # executable in a private PATH without changing process-wide state.
            tool_dir=args.output.parent/'tools';tool_dir.mkdir(parents=True,exist_ok=True)
            solver_link=tool_dir/'z3'
            if not solver_link.exists():solver_link.symlink_to(solver)
            require(solver_link.resolve()==solver,'Existing solver link changed')
            environment['PATH']=str(tool_dir)+os.pathsep+environment.get('PATH','')
        for item in cases():
            folder=artifacts/item['id']
            native=audit_native(execute([args.reference,'--policy-sequence-reference',folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ)),item)
            result['cases'][item['id']]=dict(accepted=native['accepted']);result['native_cases']+=1;result['native_steps']+=len(native['steps'])
            if not args.native_only:
                bundle=folder/'evidence'
                execution=execute([args.soundcheck,'rbac','sequence',folder/'before.json',folder/'after.json','--contract',folder/'contract.json','--format','json','--evidence-dir',bundle],folder/'production.json',environment)
                states=audit_evidence(bundle,execution.get('data'),item,args.soundcheck)
                report=audit_production(execution,item,native,states);result['model_cases']+=1
                result['cases'][item['id']]['result']=report['result']
                row=composition_witness(report,item)
                if row is not None:
                    for path in replay_witness(args.reference,folder,row,item,environment):result['input_sha256'][str(path)]=digest(path)
                    result['witness_replays']+=1;result['witness_native_checks']+=2
            save(args.output,result);print(item['id']+': frozen/native'+('' if args.native_only else '/production')+' agree',flush=True)
        for item in rejections():
            folder=artifacts/'rejections'/item['id']
            audit_native_boundary(execute([args.reference,'--policy-sequence-reference',folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ)))
            result['native_boundaries']+=1
            if not args.native_only:
                audit_production_boundary(execute([args.soundcheck,'rbac','sequence',folder/'before.json',folder/'after.json','--contract',folder/'contract.json','--format','json'],folder/'production.json',environment))
                result['model_boundaries']+=1
        for field in ['input_sha256','source_sha256','binary_sha256','upstream_source_sha256']:
            require(all(digest(Path(path))==sha for path,sha in result[field].items()),field+' changed during execution')
        audit_pins(planned_inputs(),read_json(HERE/'inputs.json'))
        result.update(inputs_unchanged=True,binaries_unchanged=True);audit_completion(result,args.native_only);result['complete']=True
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,StopIteration) as error:
        result['failures'].append(str(error))
    save(args.output,result);print({key:result[key] for key in ['complete','native_only','native_cases','native_boundaries','native_steps','model_cases','model_boundaries','witness_replays','witness_native_checks','failures']})
    return 0 if result['complete'] else 1


if __name__=='__main__':
    raise SystemExit(main())
