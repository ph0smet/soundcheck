#!/usr/bin/env python3
"""Pinned ordinary policy deletion, mixed migration and persistent-clause checks.

All fixture decisions are declared here and frozen by generate.py before native
or production execution. Native states are independently reconstructed; no
Soundcheck report or SMT formula supplies a reference expectation.
"""
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
import run_policy_sequences as sequence

HERE = Path(__file__).resolve().parent.parent / 'policy-retirement'
GROUP = change.GROUP
CHANGE_KIND = 'kubernetes-rbac-policy-change'
SEQUENCE_KIND = sequence.KIND
SOURCE_FILES = copy.deepcopy(sequence.SOURCE_FILES)
SOURCE_FILES['apiserver'] += ['pkg/endpoints/handlers/delete.go', 'pkg/registry/rest/delete.go',
    'pkg/registry/generic/registry/dryrun.go', 'pkg/storage/interfaces.go']
SOURCE_FILES['kubernetes'] += [f'pkg/registry/rbac/{kind}/storage/storage.go' for kind in ['role','clusterrole','rolebinding','clusterrolebinding']]
LINKAGE = dict(change.LINKAGE)
LINKAGE.update({
    'generic-delete': ('apiserver','pkg/registry/generic/registry/store.go',1131,'pkg/registry/generic/registry.(*Store).Delete'),
    'before-delete': ('apiserver','pkg/registry/rest/delete.go',75,'pkg/registry/rest.BeforeDelete'),
    'delete-handler': ('apiserver','pkg/endpoints/handlers/delete.go',58,'pkg/endpoints/handlers.DeleteResource')})
rule, role, binding, authority, snapshot = change.rule, change.role, change.binding, change.authority, change.snapshot
step, key, target_key = sequence.step, sequence.key, sequence.target_key
identity = sequence.identity


def requirements(changes=()):
    return sequence.requirements(changes)


def contract(steps, requirement=None, invariants=(), mode='sequence'):
    value = dict(schema_version=2, kind=SEQUENCE_KIND if mode=='sequence' else CHANGE_KIND,
                 actor='deployer', requirements=copy.deepcopy(requirement or requirements()))
    if mode=='sequence': value.update(steps=copy.deepcopy(steps), invariants=list(invariants))
    else:
        require(len(steps)==1, 'Single change requires one operation')
        value.update(copy.deepcopy(steps[0]))
    return value


def steps_for(case):
    spec=case['contract']
    return spec['steps'] if case['mode']=='sequence' else [dict(operation=spec['operation'],target=spec['target'])]


def states_for(case):
    final = {key(obj):obj for obj in case['after']['items']}
    states = [copy.deepcopy(case['before'])]
    for selected in steps_for(case):
        wanted=target_key(selected['target']); state=copy.deepcopy(states[-1]); items=state['items']
        if selected['operation']=='delete-existing':
            state['items']=[obj for obj in items if key(obj)!=wanted]
        else:
            updated=[];found=False
            for obj in items:
                if key(obj)==wanted: updated.append(copy.deepcopy(final[wanted]));found=True
                else: updated.append(obj)
            if not found: updated.append(copy.deepcopy(final[wanted]))
            state['items']=updated
        states.append(state)
    states[-1]=copy.deepcopy(case['after'])
    return states


def single_case(case,index,states=None):
    states=states or states_for(case);selected=steps_for(case)[index]
    spec=dict(schema_version=2,kind=CHANGE_KIND,actor=case['contract']['actor'],requirements=case['contract']['requirements'],**selected)
    return dict(id=case['id']+'/'+str(index+1),before=states[index],after=states[index+1],contract=spec,expected=case['expected']['steps'][index])


def case(id_,before,after,steps,decisions,mode='sequence',requirement=None,invariants=(),result=None,phase=None,
         failing_step=None,witness=None,state_checks=()):
    value=dict(id=id_,mode=mode,before=snapshot(before),after=snapshot(after),
        contract=contract(steps,requirement,invariants,mode),expected=dict(steps=[],witness=witness,state_checks=copy.deepcopy(list(state_checks))))
    states=states_for(value)
    for index,decision in enumerate(decisions):
        initial,special,covered=decision
        selected=steps[index];deleting=selected['operation']=='delete-existing'
        accepted=initial and (deleting or bool(special or covered))
        expected=dict(initial='Allow' if initial else 'NoOpinion',special=None if deleting or not initial else ('Allow' if special else 'NoOpinion'),
            covered=covered,accepted=accepted,owner_rules=[],required_rules=[],missing_rules=[],
            result='proved' if accepted else 'violated',stage='access' if accepted else 'authorization')
        value['expected']['steps'].append(expected)
        if covered is not None:
            sub=single_case(value,index,states)
            expected['owner_rules']=change.eligible_rules(sub)
            expected['required_rules']=sequence.required_rules(sub)
            expected['missing_rules']=[] if covered else change.atoms(expected['required_rules'])
    failed=next((index+1 for index,entry in enumerate(value['expected']['steps']) if not entry['accepted']),None)
    success='valid_sequence' if mode=='sequence' else 'valid_change'
    value['expected'].update(accepted=failed is None,failed_step=failed,
        result='authorization_failed' if failed else result or success,
        phase='authorization' if failed else phase or 'complete',failing_step=failed if failed else failing_step)
    return value


def check(state,clause,decision,resource='configmaps',user='app',name='settings',namespace='team-a'):
    identities={entry['username']:entry['groups'] for entry in change.IDENTITIES}
    row=dict(id=clause,username=user,groups=identities[user],operation='get',apiGroup='',resource=resource,
        namespace=namespace,name=name,resourceRequest=True,subresource='')
    return dict(state=state,clause=clause,decision=decision,request=row)


def cases():
    result=[];common=change.common();future=rule(['frobnicate'],['future.example.test'],['novelresources/arbitrary'],['one'])
    policy=lambda verbs,resources,names=None:rule(verbs,[GROUP],resources,names)
    for kind in change.RESOURCES:
        namespace='team-a' if kind in ['Role','RoleBinding'] else None
        target=role(kind,'target',namespace,[future]) if not kind.endswith('Binding') else binding(kind,'target',namespace,role_name='referenced')
        referenced=[] if not kind.endswith('Binding') else [role('ClusterRole','referenced',rules=[future])]
        for flavor,verbs,names,expected in [('ordinary',['delete'],None,True),('named',['delete'],['target'],True),
            ('wrong-name',['delete'],['other'],False),('empty-name',['delete'],[''],False),('update-only',['update'],None,False),
            ('special-only',['bind','escalate'],None,False)]:
            auth=authority([policy(verbs,[change.RESOURCES[kind]],names)])
            baseline=common+auth+referenced+[target];final=common+auth+referenced
            selected=step(kind,'delete-existing')
            result.append(case(kind.lower()+'-delete-'+flavor,baseline,final,[selected],[(expected,None,None)],mode='change'))
        auth=authority([policy(['delete'],[change.RESOURCES[kind]])])
        result.append(case(kind.lower()+'-delete-sequence',common+auth+referenced+[target],common+auth+referenced,
            [step(kind,'delete-existing')],[(True,None,None)],invariants=['required-config','forbidden-secrets'],
            state_checks=[check(s,'required-config','Allow') for s in [0,1]]+[check(s,'forbidden-secrets','NoOpinion','secrets') for s in [0,1]]))
    # Namespaced authority cannot delete a cluster target; a RoleBinding can
    # authorize deletion in its namespace, and trusted group grants are real.
    target=role('ClusterRole','target',rules=[future])
    auth=authority([policy(['delete'],['clusterroles'])],'team-a')
    result.append(case('local-authority-cannot-delete-cluster-role',common+auth+[target],common+auth,
        [step('ClusterRole','delete-existing')],[(False,None,None)],mode='change'))
    target=role('Role','target','team-a',[future])
    for namespace,subject,subject_kind,allowed in [('team-a','deployer','User',True),('team-b','deployer','User',False),('team-a','deployers','Group',True)]:
        auth=authority([policy(['delete'],['roles'],['target'])],namespace,subject=subject,subject_kind=subject_kind)
        result.append(case('local-delete-'+namespace+'-'+subject_kind.lower(),common+auth+[target],common+auth,
            [step('Role','delete-existing')],[(allowed,None,None)],mode='change'))

    broad=authority([policy(['create','update','delete','escalate','bind'],list(change.RESOURCES.values()))])
    replacement=role('Role','replacement-config','team-a',[rule(names=['settings'])])
    replacement_binding=binding('RoleBinding','replacement-config','team-a','Role','replacement-config','app')
    steps=[step('Role','create','replacement-config'),step('RoleBinding','create','replacement-config'),
        step('RoleBinding','delete-existing','required-config'),step('Role','delete-existing','required-config')]
    allowed=[(True,True,None)]*2+[(True,None,None)]*2
    scoped=requirements([change.controller.scope(names=['settings'])])
    invariant_checks=[check(s,'required-config','Allow') for s in range(5)]+[check(s,'forbidden-secrets','NoOpinion','secrets') for s in range(5)]
    baseline=common+broad;final=broad+[replacement,replacement_binding]
    result.append(case('replace-before-retire',baseline,final,steps,allowed,requirement=scoped,
        invariants=['required-config','forbidden-secrets'],state_checks=invariant_checks))
    ordered=[steps[0],steps[2],steps[1],steps[3]]
    decisions=[allowed[0],allowed[2],allowed[1],allowed[3]]
    checks=[check(s,'required-config','NoOpinion' if s==2 else 'Allow') for s in range(5)]
    witness=dict(state=2,kind='configmaps',operation='get',user='app',before='Allow',after='NoOpinion',failed='required-config',origins=[])
    result.append(case('retire-before-replacement-loses-invariant',baseline,final,ordered,decisions,requirement=scoped,
        invariants=['required-config'],result='invariant_failed',phase='state_invariants',failing_step=2,witness=witness,state_checks=checks))
    result.append(case('explicitly-final-only-migration',baseline,final,ordered,decisions,requirement=scoped,state_checks=checks))
    out_witness=copy.deepcopy(witness);out_witness.pop('failed')
    result.append(case('temporary-outside-scope-loss',baseline,final,ordered,decisions,result='out_of_scope_regression',
        phase='intermediate_preservation',failing_step=2,witness=out_witness,state_checks=checks))
    reordered=copy.deepcopy(next(c for c in result if c['id']=='replace-before-retire'));reordered['id']='candidate-order-independent';reordered['after']['items'].reverse();result.append(reordered)

    # Invariant selection includes S0; a final repair cannot erase a baseline
    # violation of a clause that the owner required throughout the transition.
    before=broad+[replacement]
    after=before+[replacement_binding]
    result.append(case('baseline-required-access-missing',before,after,[step('RoleBinding','create','replacement-config')],[(True,True,None)],
        requirement=scoped,invariants=['required-config'],result='invariant_failed',phase='state_invariants',failing_step=0,
        witness=dict(state=0,kind='configmaps',operation='get',user='app',before='NoOpinion',after='NoOpinion',failed='required-config',origins=[]),
        state_checks=[check(0,'required-config','NoOpinion'),check(1,'required-config','Allow')]))
    secret_role=role('ClusterRole','secret-reader',rules=[rule(resources=['secrets'])])
    leak=binding('RoleBinding','leak','team-a',role_name='secret-reader',subject='app')
    secret_scope=requirements([change.controller.scope(resource='secrets')])
    before=common+broad+[secret_role,leak];after=common+broad+[secret_role]
    for invariants,name in [(['forbidden-secrets'],'baseline-forbidden-access'),(['required-config'],'repair-goal-is-final-only')]:
        failure='forbidden-secrets' in invariants
        result.append(case(name,before,after,[step('RoleBinding','delete-existing','leak')],[(True,None,None)],requirement=secret_scope,invariants=invariants,
            result='invariant_failed' if failure else None,phase='state_invariants' if failure else None,failing_step=0 if failure else None,
            witness=dict(state=0,kind='secrets',operation='get',user='app',before='Allow',after='Allow',failed='forbidden-secrets',
                origins=['RoleBinding/team-a/leak -> ClusterRole/secret-reader/rules/0']) if failure else None,
            state_checks=[check(0,'forbidden-secrets','Allow','secrets'),check(1,'forbidden-secrets','NoOpinion','secrets')]))
    empty=copy.deepcopy(secret_role);empty['rules']=[]
    before=common+broad+[secret_role];after=common+broad+[empty,leak]
    result.append(case('temporary-in-scope-secret-grant',before,after,[step('RoleBinding','create','leak'),step('ClusterRole','update-existing','secret-reader')],
        [(True,True,None)]*2,requirement=secret_scope,invariants=['forbidden-secrets'],result='invariant_failed',phase='state_invariants',failing_step=1,
        witness=dict(state=1,kind='secrets',operation='get',user='app',before='NoOpinion',after='Allow',failed='forbidden-secrets',
            origins=['RoleBinding/team-a/leak -> ClusterRole/secret-reader/rules/0']),
        state_checks=[check(s,'forbidden-secrets','Allow' if s==1 else 'NoOpinion','secrets') for s in range(3)]))

    # Endpoint failures still precede invariant evaluation by the approved gate order.
    result.append(case('delete-required-access',common+broad,[common[0]]+broad,[step('RoleBinding','delete-existing','required-config')],[(True,None,None)],
        mode='change',requirement=scoped,result='contract_failed',phase='final_verification',
        witness=dict(state=1,kind='configmaps',operation='get',user='app',before='Allow',after='NoOpinion',failed='required-config',origins=[])))
    persistent=binding('RoleBinding','leftover','team-a',role_name='secret-reader',subject='app')
    result.append(case('delete-one-of-two-secret-grants',common+broad+[secret_role,leak,persistent],common+broad+[secret_role,persistent],
        [step('RoleBinding','delete-existing','leak')],[(True,None,None)],requirement=secret_scope,invariants=['forbidden-secrets'],
        result='contract_failed',phase='final_verification',failing_step=1,
        witness=dict(state=1,kind='secrets',operation='get',user='app',before='Allow',after='Allow',failed='forbidden-secrets',
            origins=['RoleBinding/team-a/leftover -> ClusterRole/secret-reader/rules/0'])))
    pods=role('ClusterRole','pods-reader',rules=[rule(resources=['pods'],names=['existing'])])
    ops=binding('RoleBinding','ops-pods','team-a',role_name='pods-reader',subject='ops')
    result.append(case('delete-unapproved-ops-access',common+broad+[pods,ops],common+broad+[pods],
        [step('RoleBinding','delete-existing','ops-pods')],[(True,None,None)],mode='change',result='out_of_scope_regression',phase='final_verification',
        witness=dict(state=1,kind='pods',operation='get',user='ops',before='Allow',after='NoOpinion',origins=[])))

    own=authority([policy(['delete','create','escalate'],['roles','clusterrolebindings'])])
    later=role('Role','later','team-a',[future])
    self_steps=[step('ClusterRoleBinding','delete-existing','actor-authority'),step('Role','create','later')]
    before=common+own;after=common+[own[0],later]
    result.append(case('delete-own-authority-then-fail',before,after,self_steps,[(True,None,None),(False,None,None)]))
    result.append(case('use-authority-before-retirement',before,after,list(reversed(self_steps)),[(True,True,None),(True,None,None)]))
    grant_role=role('ClusterRole','delegated-delete',rules=[policy(['delete'],['roles'],['target'])])
    grant=binding('RoleBinding','delegation','team-a',role_name='delegated-delete',subject='deployer')
    target=role('Role','target','team-a',[future])
    initial=authority([policy(['create'],['rolebindings']),policy(['bind'],['clusterroles'],['delegated-delete'])])
    before=common+initial+[grant_role,target];after=common+initial+[grant_role,grant]
    grant_steps=[step('RoleBinding','create','delegation'),step('Role','delete-existing','target')]
    result.append(case('grant-delete-then-use',before,after,grant_steps,[(True,True,None),(True,None,None)]))
    result.append(case('future-delete-authority-cannot-bootstrap',before,after,list(reversed(grant_steps)),[(False,None,None)]))
    many=[role('Role','retire-'+str(i),'team-a',[future]) for i in range(16)]
    result.append(case('sixteen-deletions',common+broad+many,common+broad,
        [step('Role','delete-existing','retire-'+str(i)) for i in range(16)],[(True,None,None)]*16))
    return result


def rejections():
    base=next(c for c in cases() if c['id']=='replace-before-retire');result=[]
    for name in ['repeated-target','role-before-binding','target-absent-before','target-retained-after','unapproved-removal','unapproved-addition',
                 'invariants-missing','invariants-null','invariants-unknown','invariants-duplicate','invariants-non-string',
                 'v1-invariants','v1-delete','unknown-version','patch','delete-options','finalizers','ownerReferences','deletionTimestamp','aggregate-target',
                 'seventeen-targets','zero-steps','masters-actor','late-invalid-before-authorization']:
        value=copy.deepcopy(base);value['id']=name;spec=value['contract'];before=value['before']['items'];after=value['after']['items']
        if name=='repeated-target':spec['steps'].append(copy.deepcopy(spec['steps'][2]))
        elif name=='role-before-binding':spec['steps'][2],spec['steps'][3]=spec['steps'][3],spec['steps'][2]
        elif name=='target-absent-before':before.remove(next(o for o in before if key(o)==('RoleBinding','team-a','required-config')))
        elif name=='target-retained-after':after.append(copy.deepcopy(next(o for o in before if key(o)==('RoleBinding','team-a','required-config'))))
        elif name=='unapproved-removal':spec['steps'].pop(3)
        elif name=='unapproved-addition':after.append(role('Role','unapproved','team-a'))
        elif name=='invariants-missing':spec.pop('invariants')
        elif name=='invariants-null':spec['invariants']=None
        elif name=='invariants-unknown':spec['invariants']=['not-a-clause']
        elif name=='invariants-duplicate':spec['invariants']=['required-config','required-config']
        elif name=='invariants-non-string':spec['invariants']=[True]
        elif name=='v1-invariants':spec['schema_version']=1
        elif name=='v1-delete':spec['schema_version']=1;spec.pop('invariants')
        elif name=='unknown-version':spec['schema_version']=3
        elif name=='patch':spec['steps'][0]['operation']='patch'
        elif name=='delete-options':spec['steps'][2]['delete_options']={'propagationPolicy':'Foreground'}
        elif name in ['finalizers','ownerReferences','deletionTimestamp']:before[0]['metadata'][name]=None
        elif name=='aggregate-target':
            agg=role('ClusterRole','aggregate',rules=[]);agg['aggregationRule']={'clusterRoleSelectors':[{'matchLabels':{'absent':'yes'}}]}
            before.append(agg);spec['steps'].append(step('ClusterRole','delete-existing','aggregate'))
        elif name=='seventeen-targets':
            for i in range(13):
                target=role('Role','overflow-'+str(i),'team-a');before.append(target);spec['steps'].append(step('Role','delete-existing','overflow-'+str(i)))
        elif name=='zero-steps':spec['steps']=[]
        elif name=='masters-actor':spec['requirements']['context']['identities'][-1]['groups'].append('system:masters')
        elif name=='late-invalid-before-authorization':
            for state in [before,after]:next(o for o in state if key(o)==('ClusterRole','','actor-authority'))['rules']=[]
            spec['steps'].append(step('Role','delete-existing','absent'))
        result.append(value)
    single=next(c for c in cases() if c['id']=='role-delete-ordinary')
    for name in ['single-v1-delete','single-absent','single-retained','single-extra-removal','single-finalizers']:
        value=copy.deepcopy(single);value['id']=name
        if name=='single-v1-delete':value['contract']['schema_version']=1
        elif name=='single-absent':value['before']['items'].pop()
        elif name=='single-retained':value['after']['items'].append(copy.deepcopy(value['before']['items'][-1]))
        elif name=='single-extra-removal':value['after']['items'].pop(2)
        else:value['before']['items'][-1]['metadata']['finalizers']=[]
        result.append(value)
    return result


def planned_inputs():
    output={'source-inventory.json':encoded(SOURCE_FILES),'native-linkage.json':encoded(LINKAGE)}
    for item in cases():
        for name in ['before','after','contract','expected']:
            output[item['id']+'/'+name+'.json']=encoded(item[name])
    for item in rejections():
        for name in ['before','after','contract']:
            output['rejections/'+item['id']+'/'+name+'.json']=encoded(item[name])
    return output


def initial_attributes(case):
    attrs=change.initial_attributes(case)
    if case['contract']['operation']=='delete-existing':attrs['verb']='delete'
    return attrs


def audit_delete_native(execution,case):
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native deletion command failed')
    value=execution.get('data');expected=case['expected']
    fields={'schema_version','kind','valid','validation_errors','initial','special','resolutions','coverage','actor_rules',
            'only_gc_fields','storage_calls','storage_validation','guard_accepted','accepted','error','error_reason','http_status'}
    require(isinstance(value,dict) and set(value)==fields,'Wrong native deletion shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_policy_change_native'
            and value['valid'] is True and value['validation_errors']==[],'Invalid native deletion')
    require(encoded(value['actor_rules'])==encoded(change.eligible_rules(case)),'Wrong predecessor rule inventory')
    entry=value['initial'];attrs=initial_attributes(case)
    require(isinstance(entry,dict) and set(entry)=={'attributes','decision','reason','error','granting_rule_indices'},'Missing native initial evidence')
    require(encoded(entry['attributes'])==encoded(attrs) and entry['decision']==expected['initial']
            and entry['error']=='' and isinstance(entry['reason'],str),'Wrong deletion request attributes/decision')
    indices=entry['granting_rule_indices']
    require(isinstance(indices,list) and indices==sorted(set(indices))
            and all(type(i) is int and 0<=i<len(value['actor_rules']) for i in indices)
            and bool(indices)==expected['accepted'],'Wrong named-delete granting origins')
    require(value['special']==[] and value['resolutions']==[] and value['coverage']==[],'Ordinary deletion invented bind/escalate/coverage checks')
    require(value['only_gc_fields'] is False and value['storage_validation']==[],'Deletion used an update shortcut')
    for field in ['accepted','guard_accepted']:
        require(type(value[field]) is bool and value[field] is expected['accepted'],'Wrong native deletion acceptance')
    require(type(value['storage_calls']) is int and value['storage_calls']==int(expected['accepted']),'Unexpected native persistence calls')
    require(type(value['http_status']) is int and value['http_status']==(200 if expected['accepted'] else 403),'Wrong native DELETE HTTP outcome')
    require(value['error']=='' and value['error_reason']=='','Unexpected native deletion error')
    return value


def audit_native_single(execution,case):
    if case['contract']['operation']=='delete-existing':return audit_delete_native(execution,case)
    return change.audit_native(execution,case)


def audit_native(execution,case):
    if case['mode']=='change':return audit_native_single(execution,single_case(case,0))
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native sequence command failed')
    value=execution.get('data');expected=case['expected'];states=states_for(case)
    fields={'schema_version','kind','valid','validation_errors','accepted','failed_step','state_count','states','steps'}
    require(isinstance(value,dict) and set(value)==fields,'Wrong native migration shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_policy_sequence_native','Wrong native migration identity')
    require(value['valid'] is True and value['validation_errors']==[] and type(value['accepted']) is bool
            and value['accepted'] is expected['accepted'],'Wrong native migration outcome')
    require(type(value['state_count']) is int and value['state_count']==len(states) and encoded(value['states'])==encoded(states),'Native state derivation differs')
    require(value['failed_step'] is None if expected['failed_step'] is None else
            type(value['failed_step']) is int and value['failed_step']==expected['failed_step'],'Wrong native failing step')
    require(isinstance(value['steps'],list) and len(value['steps'])==len(expected['steps']),'Native omitted or invented an executed step')
    for index,entry in enumerate(value['steps']):
        require(isinstance(entry,dict) and set(entry)=={'index','before_sha256','after_sha256','native'}
            and type(entry['index']) is int and entry['index']==index+1,'Wrong native step identity')
        for field,state in [('before_sha256',index),('after_sha256',index+1)]:
            require(entry[field]==hashlib.sha256(sequence.native_state_bytes(case,states,state)).hexdigest(),'Native state digest differs')
        audit_native_single(dict(returncode=0,data=entry['native']),single_case(case,index,states))
    return value


def audit_linkage(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native retirement linkage failed')
    value=execution.get('data')
    require(isinstance(value,dict) and value.get('kind')=='rbac_policy_retirement_native_linkage'
            and isinstance(value.get('functions'),dict) and set(value['functions'])==set(LINKAGE),'Wrong retirement linkage inventory')
    old=copy.deepcopy(value);old['kind']='rbac_policy_change_native_linkage'
    old['functions']={key:entry for key,entry in old['functions'].items() if key in change.LINKAGE}
    change.audit_linkage(dict(returncode=0,data=old))
    for label in set(LINKAGE)-set(change.LINKAGE):
        module,path,line,function=LINKAGE[label];entry=value['functions'][label]
        require(isinstance(entry,dict) and set(entry)=={'file','line','function'},'Wrong native deletion function shape')
        require(entry['function']=='k8s.io/'+module+'/'+function and type(entry['line']) is int and entry['line'] in [line,line+1]
            and entry['file'].endswith('k8s.io/'+module+'@v0.34.0/'+path),'Wrong pinned deletion function '+label)
    return value


def replay_state_checks(reference,folder,case,environment):
    states=states_for(case);checks=case['expected']['state_checks'];paths=[];count=0
    grouped={}
    for selected in checks:
        require(type(selected['state']) is int and 0<=selected['state']<len(states),'Invalid declared native state check')
        clause=next(c for c in case['contract']['requirements']['clauses'] if c['name']==selected['clause'])
        require(change.controller.scope_matches(clause,selected['request']),'Declared state check is outside its frozen clause')
        grouped.setdefault(selected['state'],[]).append(selected)
    for state,entries in grouped.items():
        snapshot_path=folder/('state-check-%03d.json'%state);request_path=folder/('state-check-%03d-urls.json'%state)
        save(snapshot_path,states[state]);rows=[entry['request'] for entry in entries]
        require(len({row['id'] for row in rows})==len(rows),'Duplicate state-check id')
        save(request_path,[change.controller.as_url(row) for row in rows])
        execution=execute([reference,'--coverage-urls',snapshot_path,request_path],folder/('state-check-%03d-native.json'%state),environment)
        decisions=change.controller.coverage.audit_native_urls(execution,rows)
        for entry in entries:require(decisions[entry['request']['id']]==entry['decision'],'Native state clause disagrees with frozen expectation')
        paths += [snapshot_path,request_path];count += len(rows)
    return paths,count


def source_provenance(metadata_file):
    metadata=read_json(metadata_file);root=Path(metadata['Dir']).parent;pins=read_json(HERE/'source-pins.json');result={}
    require(set(pins)==set(SOURCE_FILES),'Wrong pinned retirement module inventory')
    for module,files in SOURCE_FILES.items():
        require(set(pins[module])==set(files),'Wrong pinned retirement source inventory')
        for name in files:
            path=root/(module+'@'+('v1.34.0' if module=='kubernetes' else 'v0.34.0'))/name
            require(digest(path)==pins[module][name],'Changed upstream source '+str(path));result[str(path)]=pins[module][name]
    return result


def audit_completion(result,native_only=False):
    require(result.get('failures')==[] and result.get('native_only') is native_only,'Completion mode/failure differs')
    witnesses=sum(item['expected']['witness'] is not None for item in cases())
    counts=dict(native_cases=len(cases()),native_boundaries=len(rejections()),native_steps=sum(len(c['expected']['steps']) for c in cases()),
        native_state_checks=sum(len(c['expected']['state_checks']) for c in cases()),
        model_cases=0 if native_only else len(cases()),model_boundaries=0 if native_only else len(rejections()),
        witness_replays=0 if native_only else witnesses,witness_native_checks=0 if native_only else 2*witnesses)
    for name,want in counts.items():require(type(result.get(name)) is int and result[name]==want,'Missing completion counter '+name)
    expected={item['id']:dict(accepted=item['expected']['accepted']) for item in cases()}
    if not native_only:
        for item in cases():expected[item['id']]['result']=item['expected']['result']
    require(encoded(result.get('cases'))==encoded(expected),'Incomplete retirement case receipt')
    for name in ['native_linkage_verified','inputs_unchanged','binaries_unchanged']:require(result.get(name) is True,'Missing provenance '+name)



def normalized_contract(spec):
    require(isinstance(spec,dict) and isinstance(spec.get('requirements'),dict),'Malformed frozen contract')
    value=copy.deepcopy(spec)
    try:
        value['requirements']=change.controller.coverage.normalized_contract(value['requirements'])
        if 'invariants' in value:value['invariants']=sorted(value['invariants'])
    except (KeyError,TypeError,AttributeError) as error:
        raise RuntimeError('Malformed frozen contract') from error
    return value


def audit_frozen(frozen,spec):
    require(isinstance(frozen,dict) and set(frozen)=={'schema_version','kind','canonical'} and
        type(frozen['schema_version']) is int and frozen['schema_version']==2 and frozen['kind']==spec['kind']
        and isinstance(frozen['canonical'],str),'Missing schema-2 frozen identity')
    require(encoded(normalized_contract(strict_json(frozen['canonical'])))==encoded(normalized_contract(spec)),
        'Frozen actor/targets/order/invariants/requirements changed')


def audit_final(value,case):
    expected=case['expected'];final=value['verification'];spec=case['contract']['requirements']
    if not expected['accepted']:
        require(final is None,'Final verification ran after authorization failure');return
    require(isinstance(final,dict) and set(final)=={'comparison_report','candidate_report'},'Missing final comparison')
    candidate='violated' if expected['result']=='contract_failed' else 'proved'
    comparison='violated' if expected['phase']=='final_verification' else 'proved'
    sequence.audit_nested(final['candidate_report'],spec,candidate,'kubernetes-rbac-access')
    sequence.audit_nested(final['comparison_report'],spec,comparison,'kubernetes-rbac-access' if candidate=='violated' else 'rbac-repair-preservation')
    if candidate=='violated':require(encoded(final['candidate_report'])==encoded(final['comparison_report']),'Failed candidate replaced by another verdict')


def audit_invariant_report(report,case,status):
    require(isinstance(report,dict) and type(report.get('schema_version')) is int and report['schema_version']==10
        and report.get('property')=='rbac-sequence-invariants' and report.get('result')==status,'Wrong state invariant report')
    require(report.get('assurance')==dict(profile=change.controller.PROFILE,status='within_profile',findings=[]),'Wrong invariant domain profile')
    audit_frozen(report.get('frozen_spec'),case['contract'])
    if status=='proved':require(report.get('clause') is None and report.get('counterexample') is None,'Proved invariant has a witness')
    else:
        selected=report.get('clause');require(isinstance(selected,dict) and selected.get('name') in case['contract']['invariants'],'Unselected invariant failed')
        clause=next(c for c in case['contract']['requirements']['clauses'] if c['name']==selected['name'])
        require(selected.get('kind')==clause['kind'] and isinstance(report.get('counterexample'),dict),'Wrong failed invariant kind/witness')


def audit_production(execution,case,native,state_sources):
    expected=case['expected'];value=execution.get('data');mode=case['mode'];spec=case['contract'];steps=steps_for(case);states=states_for(case)
    fields={'schema_version','kind','result','reason','assurance','frozen_spec','inputs','verification'}
    if mode=='change':fields|={'authorization'}
    else:fields|={'phase','failing_step','states','steps','intermediate_preservation','state_invariants'}
    require(type(execution.get('returncode')) is int and execution['returncode']==(0 if expected['result'].startswith('valid_') else 3),'Wrong retirement gate exit')
    require(isinstance(value,dict) and set(value)==fields and type(value['schema_version']) is int and value['schema_version']==2
        and value['kind']==spec['kind'],'Wrong retirement report shape/version/kind')
    require(value['result']==expected['result'] and isinstance(value['reason'],str) and value['reason'],'Wrong retirement gate outcome')
    profile='kubernetes-rbac-v1.34-policy-'+('change' if mode=='change' else 'sequence')+'-v2'
    require(value['assurance']==dict(profile=profile,status='within_profile'),'Wrong retirement assurance')
    audit_frozen(value['frozen_spec'],spec)
    require(encoded(value['inputs'])==encoded(change.input_identities(case)),'Exact endpoint identity changed')
    if mode=='change':
        sub=single_case(case,0)
        change.audit_model(dict(returncode=0,data=dict(result='authorization_allowed' if expected['accepted'] else 'authorization_failed',
            reason='',authorization=value['authorization'])),sub,native)
        audit_final(value,case);return value
    require(value['phase']==expected['phase'],'Wrong sequence evaluation phase')
    require(value['failing_step'] is None if expected['failing_step'] is None else
            type(value['failing_step']) is int and value['failing_step']==expected['failing_step'],'Wrong sequence failing state/step')
    require(len(state_sources)==len(states),'Missing full derived state evidence')
    for index,data in enumerate(state_sources):
        require(encoded(strict_json(data.decode()))==encoded(states[index]),'Production changed independently constructed state')
    require(state_sources[0]==encoded(case['before']) and state_sources[-1]==encoded(case['after']),'Endpoint bytes were normalized')
    require(encoded(value['states'])==encoded([dict(index=i,digest=identity(data)) for i,data in enumerate(state_sources)]),'Wrong state digest inventory')
    require(isinstance(value['steps'],list) and len(value['steps'])==len(steps),'Missing declared operations')
    for index,(entry,selected) in enumerate(zip(value['steps'],steps)):
        require(isinstance(entry,dict) and set(entry)=={'index','operation','target','inputs','authorization'} and
                type(entry['index']) is int and entry['index']==index+1,'Wrong step shape/index')
        require(entry['operation']==selected['operation'] and encoded(entry['target'])==encoded(selected['target']),'Frozen step changed')
        require(encoded(entry['inputs'])==encoded(dict(before=identity(state_sources[index]),after=identity(state_sources[index+1]))),'Wrong predecessor input chain')
        if index<len(native['steps']):
            sub=single_case(case,index,states)
            change.audit_model(dict(returncode=0,data=dict(result='authorization_allowed' if sub['expected']['accepted'] else 'authorization_failed',
                authorization=entry['authorization'],reason='')),sub,native['steps'][index]['native'])
        else:require(entry['authorization'] is None,'Authorization continued after failure')
    audit_final(value,case)
    invariants=value['state_invariants'];count=len(states) if spec['invariants'] else 0
    require(isinstance(invariants,list) and len(invariants)==count,'Missing selected invariant states')
    for index,entry in enumerate(invariants):
        require(isinstance(entry,dict) and set(entry)=={'state','input','status','report'} and
                type(entry['state']) is int and entry['state']==index,'Wrong invariant state identity')
        require(encoded(entry['input'])==encoded(identity(state_sources[index])),'Invariant used wrong state')
        if expected['phase'] in ['complete','intermediate_preservation']:status='proved'
        elif expected['phase']=='state_invariants':
            status='proved' if index<expected['failing_step'] else 'violated' if index==expected['failing_step'] else 'not_executed'
        else:status='not_executed'
        require(entry['status']==status,'Wrong invariant execution status')
        if status=='not_executed':require(entry['report'] is None,'Skipped invariant fabricated report')
        else:audit_invariant_report(entry['report'],case,status)
    prefixes=value['intermediate_preservation']
    require(isinstance(prefixes,list) and len(prefixes)==len(steps)-1,'Missing prefix preservation')
    for index,entry in enumerate(prefixes,1):
        require(isinstance(entry,dict) and set(entry)=={'step','inputs','status','report'} and
                type(entry['step']) is int and entry['step']==index,'Wrong preservation prefix identity')
        require(encoded(entry['inputs'])==encoded(dict(before=identity(state_sources[0]),after=identity(state_sources[index]))),'Preservation baseline changed')
        if expected['phase']=='complete':status='proved'
        elif expected['phase']=='intermediate_preservation':
            status='proved' if index<expected['failing_step'] else 'violated' if index==expected['failing_step'] else 'not_executed'
        else:status='not_executed'
        require(entry['status']==status,'Wrong preservation execution status')
        if status=='not_executed':require(entry['report'] is None,'Skipped preservation fabricated report')
        else:sequence.audit_nested(entry['report'],spec['requirements'],status,'rbac-sequence-preservation')
    return value


def audit_production_boundary(execution,case):
    value=execution.get('data');spec=case['contract'];parse_failures={
        'repeated-target','invariants-missing','invariants-null','invariants-unknown','invariants-duplicate','invariants-non-string',
        'v1-invariants','v1-delete','unknown-version','patch','delete-options','seventeen-targets','zero-steps','masters-actor','single-v1-delete'}
    version=1 if case['id'] in parse_failures else 2
    require(type(execution.get('returncode')) is int and execution['returncode']==4,'Unsupported retirement did not exit unknown')
    require(isinstance(value,dict) and type(value.get('schema_version')) is int and value['schema_version']==version and value.get('kind')==spec['kind'],
        'Wrong boundary identity/version')
    profile='kubernetes-rbac-v1.34-policy-'+('change' if case['mode']=='change' else 'sequence')+'-v'+str(version)
    require(value.get('assurance')==dict(profile=profile,status='unsupported_or_inconclusive') and
        value.get('result')=='unknown' and isinstance(value.get('reason'),str) and value['reason'],'Boundary lost non-proof assurance')
    require(value.get('verification') is None,'Boundary executed final verification')
    if case['mode']=='change':require(value.get('authorization') is None,'Boundary executed authorization')
    else:
        require(value.get('phase')=='preparation' and value.get('failing_step') is None or
            value.get('phase')=='preparation' and type(value.get('failing_step')) is int,'Boundary phase/failure malformed')
        require(value.get('states')==[] and value.get('steps')==[] and value.get('intermediate_preservation')==[],'Boundary reached an intermediate stage')
        if version==2:require(value.get('state_invariants')==[],'Boundary generated invariant evidence')
        else:require('state_invariants' not in value,'Invalid legacy fallback gained schema2 fields')


def invariant_obligations(case):
    names=case['contract'].get('invariants',[])
    clauses=[c for c in case['contract']['requirements']['clauses'] if c['name'] in names]
    def entry(phase,index,items):return dict(id=phase+'-%02d-'%(index+1)+'-'.join(items),phase=phase,clauses=items)
    plan=[entry('inhabitance',i,[c['name']]) for i,c in enumerate(clauses)]
    pairs=[(a,b) for a in clauses if a['kind']=='must_not_grant' for b in clauses if b['kind']=='must_allow']
    plan += [entry('consistency',i,[a['name'],b['name']]) for i,(a,b) in enumerate(pairs)]
    plan += [entry('clause',i,[c['name']]) for i,c in enumerate(clauses)]
    return plan


def audit_evidence(directory,report,case,executable):
    require(isinstance(report,dict),'Missing production report for evidence audit')
    manifest=read_json(directory/'manifest.json');mode=case['mode'];spec=case['contract']
    require(type(manifest.get('schema_version')) is int and manifest['schema_version']==2 and
        manifest.get('kind')==spec['kind']+'-evidence','Wrong retirement evidence identity')
    require(encoded(manifest.get('inputs'))==encoded(report['inputs']),'Evidence endpoint identities differ')
    require(manifest.get('authorization_method')=='deterministic-native-rbac-policy-coverage','Evidence misstates authorization method')
    require(manifest.get('provenance',{}).get('executable_sha256')==digest(executable),'Evidence executable identity differs')
    artifacts=manifest.get('artifacts');require(isinstance(artifacts,list) and artifacts,'Missing artifact inventory')
    seen=set()
    for artifact in artifacts:
        require(isinstance(artifact,dict) and set(artifact)=={'path','sha256','bytes'} and isinstance(artifact['path'],str),'Malformed evidence artifact')
        relative=Path(artifact['path']);require(not relative.is_absolute() and '..' not in relative.parts and artifact['path'] not in seen,'Unsafe/duplicate artifact')
        seen.add(artifact['path']);path=directory/relative
        require(path.is_file() and not path.is_symlink() and type(artifact['bytes']) is int and artifact['bytes']==path.stat().st_size and artifact['sha256']==digest(path),'Artifact bytes/hash differ')
        require(path.stat().st_mode&0o077==0,'Evidence file is not private')
    actual={str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
    require(actual==seen|{'manifest.json'} and directory.stat().st_mode&0o077==0,'Evidence inventory/privacy differs')
    require(encoded(read_json(directory/'report.json'))==encoded(report),'Evidence report differs from execution')
    require(encoded(normalized_contract(read_json(directory/'contract.json')))==encoded(normalized_contract(spec)),'Evidence contract differs')
    require(manifest.get('verification')==('not_executed' if report['verification'] is None else 'see verification/manifest.json'),'Final evidence stage differs')
    if report['verification'] is not None:
        require('verification/manifest.json' in seen,'Missing final comparison evidence')
        final=read_json(directory/'verification/manifest.json')
        require(type(final.get('schema_version')) is int and final['schema_version']==3 and final.get('operation')=='repair_comparison',
            'Wrong nested comparison identity')
        require(encoded(final.get('inputs'))==encoded({k:dict(sha256=v['sha256'],size_bytes=v['bytes']) for k,v in report['inputs'].items()}),
            'Nested comparison endpoint identities changed')
        require(final.get('result')==report['verification']['comparison_report']['result'],'Nested comparison verdict changed')
        for field,relative,expected in [('candidate_report','candidate-report.json',report['verification']['candidate_report']),
            ('report','report.json',report['verification']['comparison_report'])]:
            require(final.get(field)==dict(path=relative,sha256=digest(directory/'verification'/relative)), 'Nested comparison report hash differs')
            require(encoded(read_json(directory/'verification'/relative))==encoded(expected),'Nested comparison report changed')
    if mode=='change':return [encoded(case['before']),encoded(case['after'])]
    require(manifest.get('phase')==report['phase'] and encoded(manifest.get('failing_step'))==encoded(report['failing_step']),'Evidence phase/state differs')
    sources=[(directory/('states/state-%03d.json'%i)).read_bytes() for i in range(len(steps_for(case))+1)]
    preservation=[]
    for item in report['intermediate_preservation']:
        index=item['step'];query='preservation/step-%03d.smt2'%index
        require(query in seen and (directory/query).stat().st_size>0,'Missing prefix formula')
        path=None if item['report'] is None else 'preservation/step-%03d-report.json'%index
        if path:require(encoded(read_json(directory/path))==encoded(item['report']),'Prefix report changed')
        preservation.append(dict(step=index,status=item['status'],query=query,report=path))
    require(encoded(manifest.get('intermediate_preservation'))==encoded(preservation),'Evidence prefix plan differs')
    planned=invariant_obligations(case);expected=[]
    for item in report['state_invariants']:
        index=item['state'];prefix='invariants/state-%03d/'%index;status=item['status']
        executed=status!='not_executed';verification=prefix+'manifest.json' if executed else None
        expected.append(dict(state=index,input=identity(sources[index]),status=status,verification=verification))
        if not executed:
            plan=read_json(directory/prefix/'plan.json')
            require(encoded(plan)==encoded(dict(state=index,input=identity(sources[index]),status='not_executed',
                queries=[dict(id=q['id'],path='queries/'+q['id']+'.smt2') for q in planned])),'Skipped invariant plan changed')
            wanted_files={prefix+'plan.json'}|{prefix+'queries/'+q['id']+'.smt2' for q in planned}
            require({x for x in seen if x.startswith(prefix)}==wanted_files,'Skipped invariant contains fabricated execution files')
            continue
        entry=read_json(directory/verification)
        require(type(entry.get('schema_version')) is int and entry['schema_version']==2 and entry.get('result')==status,'Wrong invariant evidence verdict')
        require(encoded(entry.get('config'))==encoded(dict(sha256=identity(sources[index])['sha256'],size_bytes=len(sources[index]))),'Invariant evidence bound wrong state')
        require(entry.get('soundcheck',{}).get('executable_sha256')==digest(executable),'Invariant executable changed')
        require(entry.get('obligation_plan')==dict(status='complete',reason=None),'Incomplete invariant obligation plan')
        for field in ['contract','report']:
            artifact=entry.get(field)
            require(isinstance(artifact,dict) and set(artifact)=={'path','sha256'} and artifact['path']==field+'.json'
                and artifact['sha256']==digest(directory/prefix/artifact['path']),'Invariant report/contract hash changed')
        require(encoded(normalized_contract(read_json(directory/prefix/'contract.json')))==encoded(normalized_contract(spec)),'Invariant evidence lost whole sequence identity')
        require(encoded(read_json(directory/prefix/'report.json'))==encoded(item['report']),'Invariant evidence report changed')
        obligations=entry.get('obligations');require(isinstance(obligations,list) and len(obligations)==len(planned),'Missing selected invariant obligations')
        decisive=False
        for obligation,wanted in zip(obligations,planned):
            require(isinstance(obligation,dict) and set(obligation)=={'id','phase','clauses','query','execution','solver_result','model','reason'},'Malformed invariant obligation')
            require(all(encoded(obligation.get(k))==encoded(v) for k,v in wanted.items()),'Invariant obligation kind/selected clause changed')
            query=obligation['query'];relative='queries/'+wanted['id']+'.smt2'
            require(isinstance(query,dict) and query==dict(path=relative,sha256=digest(directory/prefix/relative)), 'Invariant query hash changed')
            if decisive:
                require(obligation['execution']=='not_executed' and obligation['solver_result'] is None and obligation['model'] is None
                    and obligation['reason'] is None,'Invariant trace executed after failure')
                continue
            answer='sat' if wanted['phase']=='inhabitance' else 'unsat'
            if status=='violated' and wanted['phase']=='clause' and wanted['clauses']==[item['report']['clause']['name']]:answer='sat';decisive=True
            require(obligation['execution']=='executed' and obligation['solver_result']==answer and obligation['reason'] is None,'Wrong selected invariant trace result/order')
            require(isinstance(obligation['model'],dict) if answer=='sat' else obligation['model'] is None,'SAT/UNSAT model presence differs')
            if decisive:
                witness=item['report']['counterexample'];model=obligation['model']
                require(model.get('principal_name')==witness.get('principal') and model.get('method')==witness.get('action')
                    and encoded(model.get('object_request'))==encoded(witness.get('object_request')),'Invariant trace model differs from lifted witness')
        require(decisive==(status=='violated'),'Invariant trace lacks its decisive failure')
    require(encoded(manifest.get('state_invariants'))==encoded(expected),'Evidence omitted or rebound invariant states')
    return sources


def composition_witness(report,case):
    wanted=case['expected']['witness']
    if wanted is None:return None
    phase=case['expected']['phase']
    if phase=='state_invariants':selected=report['state_invariants'][wanted['state']]['report']
    elif phase=='intermediate_preservation':selected=report['intermediate_preservation'][wanted['state']-1]['report']
    else:selected=report['verification']['candidate_report' if case['expected']['result']=='contract_failed' else 'comparison_report']
    spec=case['contract']['requirements'];row=change.controller.witness_request(selected,spec)
    group,resource,subresource,_=change.controller.KINDS[wanted['kind']]
    require(row['username']==wanted['user'] and row['operation']==wanted['operation'] and row['apiGroup']==group
        and row['resource']==resource and row['subresource']==subresource,'Witness request differs from frozen defect')
    clause=selected.get('clause');require(isinstance(clause,dict),'Missing failed obligation')
    if 'failed' in wanted:
        expected=next(c for c in spec['clauses'] if c['name']==wanted['failed'])
        require(clause.get('name')==expected['name'] and clause.get('kind')==expected['kind']
            and change.controller.scope_matches(expected,row),'Witness outside frozen failed clause')
        if phase=='state_invariants':require(expected['name'] in case['contract']['invariants'],'Witness names unselected invariant')
    else:
        require(clause.get('name')=='preservation-outside-change-scope' and clause.get('kind')=='must_preserve'
            and not any(change.controller.scope_matches(scope,row) for scope in spec['change_scope']),'Witness inside approved change scope')
    if wanted['kind']=='configmaps':require(row['namespace']=='team-a' and row['name']=='settings','Wrong required ConfigMap witness')
    if wanted['kind']=='pods':require(row['namespace']=='team-a' and row['name']=='existing','Wrong preserved Pod witness')
    require(selected['counterexample'].get('granting_rules')==wanted['origins'],'Wrong witness granting origins')
    return row


def replay_witness(reference,folder,row,case,environment):
    wanted=case['expected']['witness'];states=states_for(case)
    request=folder/'witness-urls.json';before=folder/'witness-baseline.json';after=folder/'witness-state.json'
    save(request,[change.controller.as_url(row)]);save(before,states[0]);save(after,states[wanted['state']])
    old=execute([reference,'--coverage-urls',before,request],folder/'witness-before-native.json',environment)
    new=execute([reference,'--coverage-urls',after,request],folder/'witness-after-native.json',environment)
    sequence.audit_witness_replay(old,new,row,wanted)
    return [request,before,after]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['reference','module-metadata','output']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--soundcheck',type=Path);parser.add_argument('--z3',default='z3');parser.add_argument('--native-only',action='store_true')
    args=parser.parse_args(argv)
    result=dict(schema_version=1,kind='rbac_policy_retirement_conformance',complete=False,native_only=args.native_only,
        native_cases=0,native_boundaries=0,native_steps=0,native_state_checks=0,model_cases=0,model_boundaries=0,witness_replays=0,witness_native_checks=0,
        cases={},failures=[],input_sha256={},source_sha256={},binary_sha256={},upstream_source_sha256={},
        limitations=['Finite synthetic policy retirement checks are not live deployment evidence or a universal correctness proof.',
            'Native generic deletion uses fixture persistence. Fully visible successful operations, empty DeleteOptions and no interleaving are assumed.'])
    save(args.output,result)
    try:
        require(args.native_only or args.soundcheck is not None,'Production comparison requires --soundcheck')
        result['reference']=module_provenance(args.module_metadata);result['upstream_source_sha256']=source_provenance(args.module_metadata)
        inputs=planned_inputs();audit_pins(inputs,read_json(HERE/'inputs.json'))
        artifacts=Path(tempfile.mkdtemp(prefix='artifacts-',dir=args.output.parent))
        for name,data in inputs.items():
            path=artifacts/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);result['input_sha256'][str(path)]=digest(path)
        source=Path(__file__).resolve().parent
        paths=[HERE/'inputs.json',HERE/'source-pins.json',HERE/'generate.py',HERE/'README.md',source/'run.sh',source/'test_policy_retirement_runner.py',args.module_metadata]
        paths+=sorted(source.glob('run*.py'))+sorted((source/'oracle').glob('*.go'))+[source/'oracle/go.mod',source/'oracle/go.sum',source/'oracle/module-pins.json']
        result['source_sha256']={str(path):digest(path) for path in paths};binaries=[args.reference]
        if not args.native_only:
            solver=shutil.which(args.z3);require(solver is not None,'Z3 unavailable');solver=Path(solver).resolve();binaries += [args.soundcheck,solver]
        result['binary_sha256']={str(path):digest(path) for path in binaries};save(args.output.parent/'before-execution.json',result)
        audit_linkage(execute([args.reference,'--policy-retirement-reference-info'],args.output.parent/'native-linkage.json',dict(os.environ)))
        result['native_linkage_verified']=True
        environment=dict(os.environ)
        if not args.native_only:
            tool_dir=args.output.parent/'tools';tool_dir.mkdir(parents=True,exist_ok=True);solver_link=tool_dir/'z3'
            if not solver_link.exists():solver_link.symlink_to(solver)
            require(solver_link.resolve()==solver,'Existing solver link changed');environment['PATH']=str(tool_dir)+os.pathsep+environment.get('PATH','')
        for item in cases():
            folder=artifacts/item['id'];native_command='--policy-sequence-reference' if item['mode']=='sequence' else '--policy-change-reference'
            native=audit_native(execute([args.reference,native_command,folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ)),item)
            result['cases'][item['id']]=dict(accepted=native['accepted']);result['native_cases']+=1;result['native_steps']+=len(item['expected']['steps'])
            paths,count=replay_state_checks(args.reference,folder,item,dict(os.environ));result['native_state_checks']+=count
            for path in paths:result['input_sha256'][str(path)]=digest(path)
            if not args.native_only:
                bundle=folder/'evidence'
                execution=execute([args.soundcheck,'rbac',item['mode'],folder/'before.json',folder/'after.json','--contract',folder/'contract.json','--format','json','--evidence-dir',bundle],folder/'production.json',environment)
                states=audit_evidence(bundle,execution.get('data'),item,args.soundcheck)
                report=audit_production(execution,item,native,states);result['model_cases']+=1
                result['cases'][item['id']]['result']=report['result']
                row=composition_witness(report,item)
                if row is not None:
                    for path in replay_witness(args.reference,folder,row,item,environment):result['input_sha256'][str(path)]=digest(path)
                    result['witness_replays']+=1;result['witness_native_checks']+=2
            save(args.output,result);print(item['id']+': frozen/native'+('' if args.native_only else '/production')+' agree',flush=True)
        for item in rejections():
            folder=artifacts/'rejections'/item['id'];native_command='--policy-sequence-reference' if item['mode']=='sequence' else '--policy-change-reference'
            execution=execute([args.reference,native_command,folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ))
            (sequence.audit_native_boundary if item['mode']=='sequence' else change.audit_native_boundary)(execution)
            result['native_boundaries']+=1
            if not args.native_only:
                audit_production_boundary(execute([args.soundcheck,'rbac',item['mode'],folder/'before.json',folder/'after.json','--contract',folder/'contract.json','--format','json'],folder/'production.json',environment),item)
                result['model_boundaries']+=1
        for field in ['input_sha256','source_sha256','binary_sha256','upstream_source_sha256']:
            require(all(digest(Path(path))==sha for path,sha in result[field].items()),field+' changed during execution')
        audit_pins(planned_inputs(),read_json(HERE/'inputs.json'))
        result.update(inputs_unchanged=True,binaries_unchanged=True);audit_completion(result,args.native_only);result['complete']=True
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,StopIteration) as error:
        result['failures'].append(str(error))
    save(args.output,result);print({key:result[key] for key in ['complete','native_only','native_cases','native_boundaries','native_steps','native_state_checks','model_cases','model_boundaries','witness_replays','witness_native_checks','failures']})
    return 0 if result['complete'] else 1


if __name__=='__main__':
    raise SystemExit(main())
