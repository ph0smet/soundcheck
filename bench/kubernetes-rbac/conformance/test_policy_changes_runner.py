#!/usr/bin/env python3
"""Reject malformed or misattributed native/production policy-change evidence."""
import copy
import json
import unittest

import run_policy_changes as campaign
from test_coverage_runner import url_execution


def selected(id_='one-uncovered-atomic-permission'):
    return next(case for case in campaign.cases() if case['id']==id_)


def native_execution(case):
    expected=case['expected']; allowed=expected['accepted']
    def auth(attrs, decision, indices):
        return dict(attributes=attrs,decision=decision,reason='native fixture reason',error='',granting_rule_indices=indices)
    value=dict(schema_version=1,kind='rbac_policy_change_native',valid=True,validation_errors=[],
               initial=auth(campaign.initial_attributes(case),expected['initial'],[0] if expected['initial']=='Allow' else []),
               special=[],resolutions=[],coverage=[],actor_rules=campaign.eligible_rules(case),only_gc_fields=False,
               storage_calls=int(allowed),storage_validation=[],guard_accepted=allowed,accepted=allowed,
               error='' if allowed or expected['initial']=='NoOpinion' else 'native uncovered policy',
               error_reason='' if allowed or expected['initial']=='NoOpinion' else 'Forbidden',
               http_status=(201 if case['contract']['operation']=='create' else 200) if allowed else 403)
    if expected['special'] is not None:
        value['special']=[auth(campaign.special_attributes(case),expected['special'],[1] if expected['special']=='Allow' else [])]
    if expected['covered'] is not None:
        value['coverage']=[dict(owner_rules=expected['owner_rules'],required_rules=expected['required_rules'],
                               covered=expected['covered'],missing_rules=expected['missing_rules'])]
        attrs=campaign.initial_attributes(case);obj=campaign.target_object(case)
        if obj['kind'].endswith('Binding'):
            value['resolutions'].append(dict(kind='reference',namespace=attrs['namespace'],username='',groups=[],
                role_ref=obj['roleRef'],rules=expected['required_rules'],error=''))
        value['resolutions'].append(dict(kind='owner',namespace=attrs['namespace'],username=attrs['username'],groups=attrs['groups'],
            role_ref=None,rules=expected['owner_rules'],error=''))
    return dict(returncode=0,data=copy.deepcopy(value))


def model_execution(case, native):
    expected=case['expected']
    def auth(entry):
        attrs=entry['attributes']
        return dict(attributes=dict(verb=attrs['verb'],api_group=attrs['apiGroup'],namespace=attrs['namespace'],
            resource=attrs['resource'],subresource=attrs['subresource'],name=attrs['name']),granting_rule_indices=entry['granting_rule_indices'])
    authorization=dict(method='deterministic-native-rbac-policy-coverage',allowed=expected['accepted'],reason='fixture',
                       initial=auth(native['data']['initial']),special=None,coverage=None)
    if expected['special'] is not None:
        authorization['special']=auth(native['data']['special'][0])
    if expected['covered'] is not None:
        authorization['coverage']=dict(covered=expected['covered'],atom_count=len(campaign.atoms(expected['required_rules'])),missing=campaign.indexed_missing(case))
    return dict(returncode=0,data=dict(result='authorization_allowed' if expected['accepted'] else 'authorization_failed',
                authorization=copy.deepcopy(authorization),reason=''))


def boundary_execution():
    value=copy.deepcopy(native_execution(selected())['data'])
    value.update(valid=False,validation_errors=['outside frozen operation'],initial=None,special=[],resolutions=[],coverage=[],actor_rules=[],
                 only_gc_fields=False,storage_calls=0,storage_validation=[],guard_accepted=False,accepted=False,error='',error_reason='',http_status=0)
    return dict(returncode=1,data=value)


def linkage_execution():
    versions={module:('v1.34.0' if module=='kubernetes' else 'v0.34.0') for module in ['kubernetes','apiserver','api','apimachinery','component-helpers']}
    functions={}
    for label,(module,source,line,function) in campaign.LINKAGE.items():
        path_version='v0.0.0' if module=='component-helpers' else versions[module]
        functions[label]=dict(function='k8s.io/'+module+'/'+function,file='k8s.io/'+module+'@'+path_version+'/'+source,line=line)
    return dict(returncode=0,data=dict(schema_version=1,kind='rbac_policy_change_native_linkage',go_version='go1.24.0',
        modules={'k8s.io/'+module:version for module,version in versions.items()},functions=functions))


def composition_execution(case,native):
    spec=case['contract']['requirements'];wanted=campaign.composition_result(case)
    def report(result,comparison=False):
        return dict(schema_version=10,result=result,
            property='rbac-repair-preservation' if comparison else 'kubernetes-rbac-access',
            assurance=dict(profile=campaign.controller.PROFILE,status='within_profile',findings=[]),
            frozen_spec=dict(schema_version=10,kind=spec['kind'],canonical=json.dumps(spec)),clause=None,counterexample=None)
    candidate=report('violated' if wanted=='contract_failed' else 'proved')
    comparison=report('proved' if wanted=='valid_change' else 'violated',wanted!='contract_failed')
    if wanted!='valid_change':
        target=campaign.target_object(case)
        permission=next(obj['rules'][0] for obj in case['before']['items'] if obj['kind']=='ClusterRole' and obj['metadata']['name']==target['roleRef']['name'])
        username=target['subjects'][0]['name']
        groups=next(i['groups'] for i in spec['context']['identities'] if i['username']==username)
        witness=dict(principal=username,identity_groups=groups,action='get',
            object_request=dict(namespace='team-a',resource_kind=permission['resources'][0],name='settings'),
            granting_rules=['RoleBinding/team-a/target -> ClusterRole/referenced/rules/0'])
        if wanted=='contract_failed':
            candidate.update(counterexample=witness,clause=dict(name='forbidden-secrets',kind='must_not_grant'))
            comparison=copy.deepcopy(candidate)
        else:
            comparison.update(counterexample=witness,clause=dict(name='preservation-outside-change-scope',kind='must_preserve'))
    return dict(returncode=0 if wanted=='valid_change' else 3,data=dict(schema_version=1,kind='kubernetes-rbac-policy-change',
        result=wanted,reason='frozen composition fixture',assurance=dict(profile='kubernetes-rbac-v1.34-policy-change-v1',status='within_profile'),
        frozen_spec=dict(schema_version=1,kind='kubernetes-rbac-policy-change',canonical=json.dumps(case['contract'])),
        inputs=campaign.input_identities(case),authorization=model_execution(case,native)['data']['authorization'],
        verification=dict(candidate_report=candidate,comparison_report=comparison)))


class PolicyChangeConsumerTests(unittest.TestCase):
    def test_frozen_inventory_and_request_coordinates(self):
        campaign.audit_pins(campaign.planned_inputs(),campaign.read_json(campaign.HERE/'inputs.json'))
        self.assertEqual(len(campaign.cases()),92)
        self.assertEqual(len(campaign.rejections()),18)
        self.assertEqual(len(campaign.planned_inputs()),424)
        expected={(kind,op) for kind in campaign.RESOURCES for op in ['create','update-existing']}
        self.assertEqual({(case['contract']['target']['kind'],case['contract']['operation']) for case in campaign.cases()},expected)
        post=selected('role-create-explicit-special');put=selected('role-update-existing-explicit-special')
        binding=selected('rolebinding-local-clusterrole-bind')
        self.assertEqual(campaign.initial_attributes(post)['path'],'/apis/rbac.authorization.k8s.io/v1/namespaces/team-a/roles')
        self.assertEqual(campaign.initial_attributes(put)['path'],'/apis/rbac.authorization.k8s.io/v1/namespaces/team-a/roles/target')
        self.assertEqual(campaign.special_attributes(post)['name'],'')
        self.assertEqual(campaign.special_attributes(put)['name'],'target')
        self.assertEqual((campaign.special_attributes(binding)['namespace'],campaign.special_attributes(binding)['name']),('team-a','referenced'))
        for change in ['missing','extra','modified']:
            inputs=campaign.planned_inputs()
            if change=='missing':inputs.pop(next(iter(inputs)))
            elif change=='extra':inputs['invented.json']=b'{}'
            else:inputs[next(iter(inputs))]+=b' '
            with self.assertRaises(RuntimeError):campaign.audit_pins(inputs,campaign.read_json(campaign.HERE/'inputs.json'))

    def test_native_full_policy_operands_and_coordinates(self):
        case=selected();good=native_execution(case);campaign.audit_native(good,case)
        mutations=['namespace','name','apiVersion','caller','actor-rules','required-rules','missing-rules','covered','coverage-type',
                   'resolution-actor','resolution-namespace','gc','write','status','initial-index','index-bool','schema','exit']
        for mutation in mutations:
            value=copy.deepcopy(good);data=value['data']
            if mutation in ['namespace','name','apiVersion']:data['initial']['attributes'][mutation]='body-value'
            elif mutation=='caller':data['special'][0]['attributes']['username']='recipient'
            elif mutation=='actor-rules':data['actor_rules'].pop()
            elif mutation=='required-rules':data['coverage'][0]['required_rules'][0]['verbs']=['get']
            elif mutation=='missing-rules':data['coverage'][0]['missing_rules']=[]
            elif mutation=='covered':data['coverage'][0]['covered']=True
            elif mutation=='coverage-type':data['coverage'][0]['covered']=0
            elif mutation=='resolution-actor':data['resolutions'][0]['username']='candidate-owner'
            elif mutation=='resolution-namespace':data['resolutions'][0]['namespace']=''
            elif mutation=='gc':data['only_gc_fields']=True
            elif mutation=='write':data['storage_calls']=1
            elif mutation=='status':data['http_status']=201
            elif mutation=='initial-index':data['initial']['granting_rule_indices']=[999]
            elif mutation=='index-bool':data['initial']['granting_rule_indices']=[True]
            elif mutation=='schema':data['schema_version']=True
            else:value['returncode']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_native(value,case)

    def test_native_initial_and_special_short_circuit(self):
        for id_ in ['role-create-initial-not-granted','role-create-explicit-special','rolebinding-create-explicit-special']:
            case=selected(id_);good=native_execution(case);campaign.audit_native(good,case)
            for mutation in ['coverage','resolution','accepted','special-count']:
                value=copy.deepcopy(good);data=value['data']
                if mutation=='coverage':data['coverage']=[{}]
                elif mutation=='resolution':data['resolutions']=[{}]
                elif mutation=='accepted':data['accepted']=not data['accepted']
                else:data['special'].append({})
                with self.subTest(id=id_,mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_native(value,case)

    def test_model_full_missing_atoms_and_source_indices(self):
        case=selected();native=native_execution(case);good=model_execution(case,native)
        campaign.audit_model(good,case,native['data'])
        self.assertEqual(campaign.indexed_missing(case),[dict(proposed_rule_index=0,atom_index=7,rule=campaign.rule(['list'],resources=['secrets'],names=['two']))])
        mutations=['result','method','allowed-type','coordinates','source-index','coverage-count','covered','missing','rule-index','atom-index','atom-rule','rule-type','unknown-field','exit']
        for mutation in mutations:
            value=copy.deepcopy(good);auth=value['data']['authorization']
            if mutation=='result':value['data']['result']='authorization_allowed'
            elif mutation=='method':auth['method']='solver-proof'
            elif mutation=='allowed-type':auth['allowed']=0
            elif mutation=='coordinates':auth['special']['attributes']['name']='target'
            elif mutation=='source-index':auth['initial']['granting_rule_indices']=[1]
            elif mutation=='coverage-count':auth['coverage']['atom_count']-=1
            elif mutation=='covered':auth['coverage']['covered']=True
            elif mutation=='missing':auth['coverage']['missing']=[]
            elif mutation=='rule-index':auth['coverage']['missing'][0]['proposed_rule_index']=1
            elif mutation=='atom-index':auth['coverage']['missing'][0]['atom_index']=0
            elif mutation=='atom-rule':auth['coverage']['missing'][0]['rule']['resourceNames']=['one']
            elif mutation=='rule-type':auth['coverage']['missing'][0]['rule']['verbs']=[None]
            elif mutation=='unknown-field':auth['coverage']['missing'][0]['rule']['unknown']=[]
            else:value['returncode']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_model(value,case,native['data'])

    def test_model_skipped_checks_cannot_be_invented(self):
        for id_ in ['role-create-initial-not-granted','role-create-explicit-special']:
            case=selected(id_);native=native_execution(case);good=model_execution(case,native);campaign.audit_model(good,case,native['data'])
            value=copy.deepcopy(good);value['data']['authorization']['coverage']=dict(covered=True,atom_count=0,missing=[])
            with self.assertRaises(RuntimeError):campaign.audit_model(value,case,native['data'])
        case=selected('role-create-initial-not-granted');native=native_execution(case);value=model_execution(case,native)
        value['data']['authorization']['special']={}
        with self.assertRaises(RuntimeError):campaign.audit_model(value,case,native['data'])

    def test_unsupported_boundaries_do_not_yield_authorization(self):
        good=boundary_execution();campaign.audit_native_boundary(good)
        for mutation in ['accepted','initial','validation','storage','schema']:
            value=copy.deepcopy(good)
            if mutation=='accepted':value['data']['accepted']=True
            elif mutation=='initial':value['data']['initial']={}
            elif mutation=='validation':value['data']['validation_errors']=[]
            elif mutation=='storage':value['data']['storage_calls']=False
            else:value['data']['schema_version']=True
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_native_boundary(value)
        model=dict(returncode=0,data=dict(result='unknown',authorization=None,reason='unsupported operation'))
        campaign.audit_model_boundary(model)
        for mutation in ['result','authorization','reason','exit']:
            value=copy.deepcopy(model)
            if mutation=='result':value['data']['result']='authorization_failed'
            elif mutation=='authorization':value['data']['authorization']={}
            elif mutation=='reason':value['data']['reason']=''
            else:value['returncode']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_model_boundary(value)

    def test_native_source_linkage_is_pinned(self):
        good=linkage_execution();campaign.audit_linkage(good)
        for mutation in ['module','modules-type','function','file','line','missing','extra','schema','exit']:
            value=copy.deepcopy(good);data=value['data']
            if mutation=='module':data['modules']['k8s.io/component-helpers']='v0.35.0'
            elif mutation=='modules-type':data['modules']=[]
            elif mutation in ['function','file','line']:data['functions']['covers'][mutation]='invented'
            elif mutation=='missing':data['functions'].pop('role-update')
            elif mutation=='extra':data['functions']['fake']={}
            elif mutation=='schema':data['schema_version']=True
            else:value['returncode']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_linkage(value)

    def test_completion_rejects_partial_or_unsealed_evidence(self):
        good=dict(failures=[],native_only=False,native_cases=92,native_boundaries=18,model_cases=92,model_boundaries=18,
                  composition_cases=4,composition_access_witness_replays=1,composition_preservation_witness_replays=2,
                  composition_native_checks=6,compositions={case['id']:campaign.composition_result(case) for case in campaign.composition_cases()},
                  cases={case['id']:case['expected']['accepted'] for case in campaign.cases()},
                  inputs_unchanged=True,binaries_unchanged=True,native_linkage_verified=True)
        campaign.audit_completion(good)
        for mutation in ['counter','case','case-type','mode','inputs','binary','linkage','composition','replay','native-checks']:
            value=copy.deepcopy(good)
            if mutation=='counter':value['model_boundaries']=0
            elif mutation=='case':value['cases'].pop(next(iter(value['cases'])))
            elif mutation=='case-type':value['cases'][next(iter(value['cases']))]=0
            elif mutation=='mode':value['native_only']=True
            elif mutation=='inputs':value['inputs_unchanged']=False
            elif mutation=='binary':value['binaries_unchanged']=False
            elif mutation=='linkage':value['native_linkage_verified']=False
            elif mutation=='composition':value['compositions'].pop(next(iter(value['compositions'])))
            elif mutation=='replay':value['composition_preservation_witness_replays']=0
            else:value['composition_native_checks']=0
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_completion(value)
        native_only=copy.deepcopy(good);native_only.update(native_only=True,model_cases=0,model_boundaries=0,
            composition_cases=0,composition_access_witness_replays=0,composition_preservation_witness_replays=0,
            composition_native_checks=0,compositions={})
        campaign.audit_completion(native_only,True)

    def test_composed_stages_frozen_identity_and_input_bytes(self):
        self.assertEqual([campaign.composition_result(c) for c in campaign.composition_cases()],
            ['contract_failed','out_of_scope_regression','valid_change','out_of_scope_regression'])
        for case in campaign.composition_cases():
            native=native_execution(case);good=composition_execution(case,native)
            campaign.audit_composition(good,case,native['data'])
            for mutation in ['result','exit','schema','profile','actor','scope','inputs','bytes-type','authorization','candidate','candidate-profile','candidate-identity','comparison-stage']:
                value=copy.deepcopy(good);data=value['data'];frozen=copy.deepcopy(case['contract'])
                if mutation=='result':data['result']='unknown'
                elif mutation=='exit':value['returncode']=False
                elif mutation=='schema':data['schema_version']=True
                elif mutation=='profile':data['assurance']['profile']=campaign.controller.PROFILE
                elif mutation=='actor':frozen['actor']='app';data['frozen_spec']['canonical']=json.dumps(frozen)
                elif mutation=='scope':frozen['requirements']['change_scope']=[campaign.controller.scope(resource='secrets')];data['frozen_spec']['canonical']=json.dumps(frozen)
                elif mutation=='inputs':data['inputs']['before']['sha256']=data['inputs']['after']['sha256']
                elif mutation=='bytes-type':data['inputs']['before']['bytes']=True
                elif mutation=='authorization':data['authorization']['initial']['attributes']['name']='target'
                elif mutation=='candidate':data['verification']['candidate_report']=None
                elif mutation=='candidate-profile':data['verification']['candidate_report']['assurance']['status']='unsupported'
                elif mutation=='candidate-identity':
                    frozen['requirements']['context']['identities'][0]['groups']=['invented']
                    data['verification']['candidate_report']['frozen_spec']['canonical']=json.dumps(frozen['requirements'])
                else:data['verification']['comparison_report']['property']='unexpected-stage'
                with self.subTest(case=case['id'],mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_composition(value,case,native['data'])

    def test_composed_witness_obligation_identity_and_grant_origin(self):
        for case in campaign.composition_cases():
            native=native_execution(case);value=composition_execution(case,native)['data']
            row=campaign.composition_witness(value,case)
            if campaign.composition_result(case)=='valid_change':
                self.assertIsNone(row);continue
            for mutation in ['principal','groups','verb','namespace','kind','clause','grant-origin','grant-count']:
                changed=copy.deepcopy(value)
                report=changed['verification']['candidate_report' if changed['result']=='contract_failed' else 'comparison_report']
                witness=report['counterexample']
                if mutation=='principal':witness['principal']='deployer';witness['identity_groups']=['deployers']
                elif mutation=='groups':witness['identity_groups']=['invented']
                elif mutation=='verb':witness['action']='list'
                elif mutation=='namespace':witness['object_request']['namespace']='team-b'
                elif mutation=='kind':witness['object_request']['resource_kind']='nodes'
                elif mutation=='clause':report['clause']['name']='different-obligation'
                elif mutation=='grant-origin':witness['granting_rules']=['RoleBinding/team-a/invented -> ClusterRole/referenced/rules/0']
                else:witness['granting_rules']=[]
                with self.subTest(case=case['id'],mutation=mutation),self.assertRaises(RuntimeError):campaign.composition_witness(changed,case)
            if value['result']=='out_of_scope_regression':
                altered=copy.deepcopy(case)
                altered['contract']['requirements']['change_scope']=[campaign.controller.scope(resource=row['resource'],namespace=row['namespace'],names=[row['name']],subject=row['username'])]
                with self.assertRaises(RuntimeError):campaign.composition_witness(value,altered)

    def test_composed_witness_replay_requires_real_native_grant_change(self):
        case=selected('authorized-binding-loses-preservation')
        row=campaign.composition_witness(composition_execution(case,native_execution(case))['data'],case)
        before=url_execution([row],['NoOpinion']);after=url_execution([row],['Allow'])
        campaign.audit_composition_replay(before,after,row)
        for mutation in ['already-allowed','still-ungranted','wrong-caller','wrong-name','missing']:
            old,new=copy.deepcopy(before),copy.deepcopy(after)
            if mutation=='already-allowed':old['data']['decisions'][0]['decision']='Allow'
            elif mutation=='still-ungranted':new['data']['decisions'][0]['decision']='NoOpinion'
            elif mutation=='wrong-caller':new['data']['decisions'][0]['attributes']['username']='app'
            elif mutation=='wrong-name':new['data']['decisions'][0]['attributes']['name']='other'
            else:new['data']['decisions']=[]
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):campaign.audit_composition_replay(old,new,row)


if __name__=='__main__':
    unittest.main()
