#!/usr/bin/env python3
"""Adversarial consumers for controller-API evidence; no solver is invoked."""
import copy
import json
import unittest

import run_controller_apis as campaign
from test_coverage_runner import url_execution


def linkage_execution():
    versions = {'kubernetes':'v1.34.0','apiserver':'v0.34.0','apiextensions-apiserver':'v0.34.0','api':'v0.34.0','apimachinery':'v0.34.0'}
    return dict(returncode=0, data=dict(schema_version=1, kind='rbac_controller_native_linkage', go_version='go1.24.0',
        modules={'k8s.io/'+m:v for m,v in versions.items()},
        functions={label:dict(function='k8s.io/'+module+'/'+function,file='k8s.io/'+module+'@'+versions[module]+'/'+source,line=line)
            for label,(module,source,line,function) in campaign.LINKAGE.items()},
        discovery=campaign.expected_discovery(),routes=campaign.expected_routes(),
        allow_create_on_update={k:False for k in ['validatingwebhookconfigurations','mutatingwebhookconfigurations','customresourcedefinitions','customresourcedefinitions/status']}))


def review_execution():
    decisions = []
    for row in campaign.review_experiments():
        body = json.loads(row['body']); resource = row['url'].rsplit('/',1)[1]
        allowed = row['username']=='app'; group = body['apiVersion'].split('/')[0]
        entry = dict(id=row['id'],initial='Allow' if allowed else 'NoOpinion',status_code=201 if allowed else 403,
            attributes=dict(username=row['username'],groups=row['groups'],verb='create',apiGroup=group,apiVersion='v1',
                resource=resource,namespace='',name='',subresource='',resourceRequest=True,path=row['url']),
            review_calls=1 if allowed else 0,review_attributes=None,authenticated_token='',response={})
        if not allowed:
            entry['response'] = dict(kind='Status',reason='Forbidden',code=403)
        elif resource=='subjectaccessreviews':
            spec=body['spec']; a=spec['resourceAttributes']
            entry['review_attributes'] = dict(username=spec['user'],groups=spec['groups'],verb=a['verb'],apiGroup=a['group'],apiVersion=a['version'],
                resource=a['resource'],namespace=a['namespace'],name=a['name'],subresource='',resourceRequest=True,path='')
            outcome=spec['user']=='reviewed-allowed'
            entry['response'] = dict(status=dict(allowed=outcome,denied=not outcome))
        else:
            token=body['spec']['token']; entry['authenticated_token']=token
            entry['response'] = dict(status=dict(authenticated=token=='fixture-valid-token',user=dict(username='reviewed-token-user')))
        decisions.append(entry)
    return dict(returncode=0,data=dict(schema_version=1,kind='rbac_controller_review_authorization',valid=True,validation_errors=[],decisions=decisions))


class ControllerEvidenceTests(unittest.TestCase):
    def test_frozen_inputs_domains_and_literal_urls(self):
        campaign.audit_pins(campaign.planned_inputs(),campaign.read_json(campaign.HERE/'inputs.json'))
        rows=campaign.matrix_requests()
        self.assertEqual(len(rows),164)
        self.assertEqual(len(campaign.matrix_cases()),21)
        self.assertEqual(len(campaign.contract_cases()),48)
        self.assertEqual(sum(len(x[4]) for x in campaign.NEW_CATALOGUE),29)
        for row in rows:campaign.validate_request(row)
        for row in campaign.rejection_requests():
            with self.subTest(id=row['id']), self.assertRaises(RuntimeError):campaign.validate_request(row)
        for group,resource,sub,_,ops in campaign.NEW_CATALOGUE:
            for op in ops:
                self.assertEqual({r['username'] for r in rows if campaign.is_new(r) and (r['apiGroup'],r['resource'],r['subresource'],r['operation'])==(group,resource,sub,op)},set(campaign.IDENTITIES))
        examples = [
            (campaign.request('authorization.k8s.io','subjectaccessreviews',operation='create',namespace='',name=''), 'POST', '/apis/authorization.k8s.io/v1/subjectaccessreviews'),
            (campaign.request('authentication.k8s.io','tokenreviews',operation='create',namespace='',name=''), 'POST', '/apis/authentication.k8s.io/v1/tokenreviews'),
            (campaign.request('apiextensions.k8s.io','customresourcedefinitions','status','patch','','settings'), 'PATCH', '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/settings/status'),
            (campaign.request('admissionregistration.k8s.io','validatingwebhookconfigurations',operation='watch',namespace='',name='settings'), 'GET', '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations?watch=true&fieldSelector=metadata.name%3Dsettings'),
            (campaign.request('admissionregistration.k8s.io','mutatingwebhookconfigurations',operation='deletecollection',namespace='',name=''), 'DELETE', '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations')]
        for row,method,url in examples:
            self.assertEqual(campaign.as_url(row)['method'],method)
            self.assertEqual(campaign.as_url(row)['url'],url)
        self.assertEqual(len(campaign.expected_routes()),36)
        for modification in ['missing','changed','extra']:
            inputs=campaign.planned_inputs()
            if modification=='missing':inputs.pop('native-routes.json')
            elif modification=='changed':inputs['reviews/requests.json']+=b' '
            else:inputs['extra']=b'{}'
            with self.assertRaises(RuntimeError):campaign.audit_pins(inputs,campaign.read_json(campaign.HERE/'inputs.json'))

    def test_native_installer_and_linkage_cannot_be_fabricated(self):
        good=linkage_execution();campaign.audit_linkage(good)
        for mutation in ['version','scope','verbs','extra-resource','missing-route','named-review-route','put','bool-put','function','file','line','missing-function','exit']:
            value=copy.deepcopy(good);data=value['data']
            if mutation=='version':data['modules']['k8s.io/apiextensions-apiserver']='v0.35.0'
            elif mutation=='scope':data['discovery']['subjectaccessreviews.authorization.k8s.io']['scope']='Namespaced'
            elif mutation=='verbs':data['discovery']['tokenreviews.authentication.k8s.io']['verbs'].append('get')
            elif mutation=='extra-resource':data['discovery']['extra']={}
            elif mutation=='missing-route':data['routes'].pop()
            elif mutation=='named-review-route':data['routes'].append('POST /apis/authorization.k8s.io/v1/subjectaccessreviews/{name}')
            elif mutation=='put':data['allow_create_on_update']['customresourcedefinitions']=True
            elif mutation=='bool-put':data['allow_create_on_update']['customresourcedefinitions']=0
            elif mutation=='missing-function':data['functions'].pop('api-installer')
            elif mutation=='exit':value['returncode']=False
            else:data['functions']['token-review-create'][mutation]='wrong'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):campaign.audit_linkage(value)

    def test_full_native_request_tuple_remains_strict(self):
        rows=[campaign.request('authorization.k8s.io','subjectaccessreviews',operation='create',namespace='',name=''),
              campaign.request('apiextensions.k8s.io','customresourcedefinitions','status','update','','settings',id_='status')]
        good=url_execution(rows,['Allow','NoOpinion'])
        campaign.coverage.audit_native_urls(good,rows)
        for key in ['username','groups','verb','apiGroup','apiVersion','resource','namespace','name','subresource','resourceRequest','path']:
            value=copy.deepcopy(good);value['data']['decisions'][0]['attributes'][key]=[] if key=='groups' else 'wrong'
            if key=='groups':value['data']['decisions'][0]['attributes'][key]=['invented']
            with self.subTest(key=key), self.assertRaises(RuntimeError):campaign.coverage.audit_native_urls(value,rows)

    def test_body_result_never_becomes_initial_caller_result(self):
        good=review_execution();rows=campaign.review_experiments();campaign.audit_review(good,rows)
        for mutation in ['initial','caller','body-namespace','initial-name','body-identity','body-result','body-bool','status','calls','bool-calls','unauthorized-calls','token','authenticated','missing','duplicate','exit','schema']:
            value=copy.deepcopy(good);result=value['data'];entry=result['decisions'][0]
            if mutation=='initial':entry['initial']='NoOpinion'
            elif mutation=='caller':entry['attributes']['username']='reviewed-allowed'
            elif mutation=='body-namespace':entry['attributes']['namespace']='body-namespace'
            elif mutation=='initial-name':entry['attributes']['name']='body-name'
            elif mutation=='body-identity':entry['review_attributes']['username']='app'
            elif mutation=='body-result':entry['response']['status']['allowed']=False
            elif mutation=='body-bool':entry['response']['status']['denied']=0
            elif mutation=='status':entry['status_code']=403
            elif mutation=='calls':entry['review_calls']=0
            elif mutation=='bool-calls':entry['review_calls']=True
            elif mutation=='unauthorized-calls':result['decisions'][1]['review_calls']=1
            elif mutation=='token':result['decisions'][4]['authenticated_token']='other'
            elif mutation=='authenticated':result['decisions'][4]['response']['status']['authenticated']=False
            elif mutation=='missing':result['decisions'].pop()
            elif mutation=='duplicate':result['decisions'][1]=copy.deepcopy(entry)
            elif mutation=='exit':value['returncode']=1
            else:result['schema_version']=True
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):campaign.audit_review(value,rows)

    def test_report_identity_and_old_profile_are_exact(self):
        spec=campaign.contract()
        proof=dict(returncode=0,data=dict(schema_version=10,result='proved',property='kubernetes-rbac-access',assurance=dict(profile=campaign.PROFILE,status='within_profile',findings=[]),frozen_spec=dict(schema_version=10,kind=spec['kind'],canonical=json.dumps(spec)),clause=None,counterexample=None))
        campaign.audit_report(proof,spec,'proved')
        for mutation in ['profile','frozen-version','identity','catalogue','clause','request-kind','exit']:
            value=copy.deepcopy(proof);fixed=copy.deepcopy(spec)
            if mutation=='profile':value['data']['assurance']['profile']=campaign.coverage.PROFILE
            elif mutation=='frozen-version':value['data']['frozen_spec']['schema_version']=9
            elif mutation=='exit':value['returncode']=False
            else:
                if mutation=='identity':fixed['context']['identities'][0]['groups']=['extra']
                elif mutation=='catalogue':fixed['custom_resources']=[]
                elif mutation=='clause':fixed['clauses'][0]['names']=['different']
                else:fixed['clauses'][0]['request_kind']='non_resource'
                value['data']['frozen_spec']['canonical']=json.dumps(fixed)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):campaign.audit_report(value,spec,'proved')
        legacy=copy.deepcopy(spec);legacy['schema_version']=9
        old=copy.deepcopy(proof);old['data']['assurance']['profile']=campaign.coverage.PROFILE;old['data']['frozen_spec'].update(schema_version=9,canonical=json.dumps(legacy))
        campaign.audit_report(old,legacy,'proved')
        with self.assertRaises(RuntimeError):campaign.audit_report(old,spec,'proved')

    def test_review_witness_requires_empty_name_and_frozen_identity(self):
        case=next(c for c in campaign.contract_cases() if c['id']=='subjectaccessreviews-unmentioned-v10')
        witness=dict(counterexample=dict(principal='ops',identity_groups=['operators'],action='create',object_request=dict(namespace='',resource_kind='subjectaccessreviews.authorization.k8s.io',name=''),granting_rules=[]),clause=dict(name='preservation-outside-change-scope',kind='must_preserve'))
        campaign.audit_witness(witness,case,True)
        for mutation in ['name','namespace','operation','groups','kind','approved']:
            value=copy.deepcopy(witness);changed=copy.deepcopy(case)
            if mutation in ['name','namespace']:value['counterexample']['object_request'][mutation]='body-value'
            elif mutation=='operation':value['counterexample']['action']='get'
            elif mutation=='groups':value['counterexample']['identity_groups']=[]
            elif mutation=='kind':value['counterexample']['object_request']['resource_kind']='tokenreviews.authentication.k8s.io'
            else:changed['contract']['change_scope']=[campaign.scope(group='authorization.k8s.io',resource='subjectaccessreviews',operation='create',namespace=None,names={'empty':True},subject='ops')]
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):campaign.audit_witness(value,changed,True)
        self.assertEqual(campaign.finite_rows(next(c for c in campaign.contract_cases() if c['id']=='subjectaccessreviews-unmentioned-v9')), [r for r in campaign.matrix_requests() if not campaign.is_new(r)])

    def test_completion_rejects_missing_counter_case_or_provenance(self):
        result=dict(failures=[],native_only=True,**campaign.planned_counts(True),inputs_unchanged=True,binaries_unchanged=True,native_linkage_verified=True,cases={})
        result['cases']={'matrix/'+c['id']:dict(matrix_comparisons=len(campaign.matrix_requests())) for c in campaign.matrix_cases()}
        result['cases'].update({'contracts/'+c['id']:dict(native_contract=c['expected'],native_comparison=c['comparison']) for c in campaign.contract_cases()})
        campaign.audit_completion(result,True)
        for mutation in ['count','case','mode','linkage','hashes','reviews']:
            value=copy.deepcopy(result)
            if mutation=='count':value['matrix_comparisons']=0
            elif mutation=='case':value['cases'].pop(next(iter(value['cases'])))
            elif mutation=='mode':value['native_only']=False
            elif mutation=='linkage':value['native_linkage_verified']=False
            elif mutation=='hashes':value['inputs_unchanged']=False
            else:value['review_handler_checks']=0
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):campaign.audit_completion(value,True)


if __name__=='__main__':unittest.main()
