#!/usr/bin/env python3
"""Pinned schema-10 controller API authorization against Kubernetes 1.34.0.

Expected scopes, classes and outcomes are declared before production runs.
The native installer checks the selected route families; initial authorization
still does not establish body validity, review results or operation success.
"""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (DNS_SUBDOMAIN, EXIT_CODES, decisions, digest, execute, module_provenance,
                 read_json, require, save, smt_decisions, strict_json, strings, valid_dns)
from run_resources import IDENTITIES, rule, grant, snapshot, encoded, byte_hash, audit_pins
import run_coverage as coverage

HERE = Path(__file__).resolve().parent.parent/'controller-apis'
PROFILE = 'kubernetes-rbac-v1.34-controller-apis-v1'
VERBS = ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection']
NEW_CATALOGUE = [
    ('admissionregistration.k8s.io', 'validatingwebhookconfigurations', '', False, VERBS),
    ('admissionregistration.k8s.io', 'mutatingwebhookconfigurations', '', False, VERBS),
    ('apiextensions.k8s.io', 'customresourcedefinitions', '', False, VERBS),
    ('apiextensions.k8s.io', 'customresourcedefinitions', 'status', False, ['get', 'update', 'patch']),
    ('authorization.k8s.io', 'subjectaccessreviews', '', False, ['create']),
    ('authentication.k8s.io', 'tokenreviews', '', False, ['create'])]
KINDS = dict(coverage.KINDS)
KINDS.update({r+('/'+s if s else '')+'.'+g: (g,r,s,ns) for g,r,s,ns,_ in NEW_CATALOGUE})
NEW_KEYS = {x[:3] for x in NEW_CATALOGUE}
SOURCE_FILES = {
 'kubernetes': [
  'pkg/registry/admissionregistration/validatingwebhookconfiguration/strategy.go',
  'pkg/registry/admissionregistration/validatingwebhookconfiguration/storage/storage.go',
  'pkg/registry/admissionregistration/mutatingwebhookconfiguration/strategy.go',
  'pkg/registry/admissionregistration/mutatingwebhookconfiguration/storage/storage.go',
  'pkg/registry/admissionregistration/rest/storage_apiserver.go',
  'pkg/registry/authorization/subjectaccessreview/rest.go',
  'pkg/registry/authorization/rest/storage_authorization.go',
  'pkg/registry/authentication/tokenreview/storage.go',
  'pkg/registry/authentication/rest/storage_authentication.go',
  'pkg/apis/authorization/validation/validation.go',
  'plugin/pkg/auth/authorizer/rbac/rbac.go','pkg/registry/rbac/validation/rule.go'],
 'apiserver': ['pkg/endpoints/installer.go','pkg/endpoints/groupversion.go',
  'pkg/endpoints/request/requestinfo.go','pkg/endpoints/filters/authorization.go',
  'pkg/endpoints/filters/requestinfo.go','pkg/registry/rest/rest.go',
  'pkg/registry/generic/registry/store.go'],
 'apiextensions-apiserver': ['pkg/registry/customresourcedefinition/strategy.go',
  'pkg/registry/customresourcedefinition/etcd.go','pkg/apiserver/apiserver.go']}
LINKAGE = {
 'api-installer': ('apiserver','pkg/endpoints/groupversion.go',106,'pkg/endpoints.(*APIGroupVersion).InstallREST'),
 'request-info': ('apiserver','pkg/endpoints/filters/requestinfo.go',28,'pkg/endpoints/filters.WithRequestInfo'),
 'request-classifier': ('apiserver','pkg/endpoints/request/requestinfo.go',129,'pkg/endpoints/request.(*RequestInfoFactory).NewRequestInfo'),
 'authorization-filter': ('apiserver','pkg/endpoints/filters/authorization.go',53,'pkg/endpoints/filters.WithAuthorization'),
 'authorizer-attributes': ('apiserver','pkg/endpoints/filters/authorization.go',101,'pkg/endpoints/filters.GetAuthorizerAttributes'),
 'rbac-authorizer': ('kubernetes','plugin/pkg/auth/authorizer/rbac/rbac.go',75,'plugin/pkg/auth/authorizer/rbac.(*RBACAuthorizer).Authorize'),
 'subject-access-review-create': ('kubernetes','pkg/registry/authorization/subjectaccessreview/rest.go',63,'pkg/registry/authorization/subjectaccessreview.(*REST).Create'),
 'token-review-create': ('kubernetes','pkg/registry/authentication/tokenreview/storage.go',69,'pkg/registry/authentication/tokenreview.(*REST).Create')}

scope = coverage.scope
clause = coverage.clause
request = coverage.request
scope_matches = coverage.scope_matches
as_url = coverage.as_url


def contract(clauses=None, changes=()):
    value = coverage.contract(clauses, changes)
    value['schema_version'] = 10
    return value


def is_new(row):
    return row.get('resourceRequest') is True and (row.get('apiGroup'),row.get('resource'),row.get('subresource')) in NEW_KEYS


def validate_request(row, identities=IDENTITIES, custom=coverage.CUSTOM):
    if not is_new(row):
        return coverage.validate_request(row, identities, custom)
    require(set(row) == {'id','username','groups','operation','resourceRequest','apiGroup','resource','subresource','namespace','name'}, 'Wrong new request shape')
    require(isinstance(row['id'],str) and row['id'] and type(row['resourceRequest']) is bool, 'Invalid request discriminator/id')
    require(row['username'] in identities and strings(row['groups'],nonempty=True)
        and sorted(row['groups']) == sorted(identities[row['username']]) and len(set(row['groups'])) == len(row['groups']), 'Wrong frozen identity')
    entry = next(x for x in NEW_CATALOGUE if x[:3] == (row['apiGroup'],row['resource'],row['subresource']))
    require(row['operation'] in entry[4], 'Unsupported controller API operation')
    require(row['namespace'] == '', 'Controller APIs are cluster scoped')
    if row['operation'] in ['create','deletecollection']:
        require(row['name'] == '', 'Collection write name must be empty')
    else:
        require((row['operation'] in ['list','watch'] and row['name'] == '') or valid_dns(row['name'],253,DNS_SUBDOMAIN), 'Invalid authorization name')


def matrix_requests():
    rows=[]
    for group,resource,subresource,_,operations in NEW_CATALOGUE:
        for operation in operations:
            names = [''] if operation in ['create','deletecollection'] else ['settings','other','fresh-name'] + ([''] if operation in ['list','watch'] else [])
            for name in names:
                for user in IDENTITIES:
                    rows.append(request(group,resource,subresource,operation,'',name,user,str(len(rows))))
    for user in IDENTITIES:
        for resource,ns,name in [('configmaps','team-a','settings'),('secrets','team-a','other'),('secrets','team-b','fresh-name')]:
            rows.append(request(resource=resource,namespace=ns,name=name,user=user,id_=str(len(rows))))
        rows.append(request('widgets.example.test','widgets','status','update','team-b','settings',user,str(len(rows))))
        rows.append(coverage.url_request('/healthz',user=user,id_=str(len(rows))))
    return rows


def matrix_cases():
    rows=matrix_requests(); cases=[]
    def add(id_,items,predicate):
        cases.append(dict(id=id_,snapshot=snapshot(items),expected={r['id']:dict(decision='Allow' if predicate(r) else 'NoOpinion',stages=['Allow' if predicate(r) else 'NoOpinion']) for r in rows}))
    app=lambda r:r['username']=='app'
    res=lambda r:r['resourceRequest']
    add('empty',[],lambda r:False)
    add('all-resource-grants',grant('all',[rule(('*',),('*',),['*'])]),lambda r:app(r) and res(r))
    add('nonresource-does-not-grant-controller',grant('urls',[dict(verbs=['*'],nonResourceURLs=['*'])]),lambda r:app(r) and not res(r))
    for local_role in [True,False]:
        add('local-role' if local_role else 'local-clusterrole',grant('local',[rule(('*',),('*',),['*'])],'team-a',local_role=local_role),lambda r:app(r) and res(r) and r['namespace']=='team-a')
    for group in ['admissionregistration.k8s.io','apiextensions.k8s.io','authorization.k8s.io','authentication.k8s.io']:
        add('group-'+group,grant('group',[rule((group,),('*',),['*'])]),lambda r,g=group:app(r) and res(r) and r['apiGroup']==g)
    add('wrong-group',grant('wrong',[rule(('extensions',),('customresourcedefinitions','subjectaccessreviews','tokenreviews'),['*'])]),lambda r:False)
    add('crd-parent-only',grant('parent',[rule(('apiextensions.k8s.io',),('customresourcedefinitions',),['*'])]),lambda r:app(r) and res(r) and r['apiGroup']=='apiextensions.k8s.io' and r['resource']=='customresourcedefinitions' and r['subresource']=='')
    add('status-wildcard',grant('status',[rule(('*',),('*/status',),['*'])]),lambda r:app(r) and res(r) and r['subresource']=='status')
    add('parent-slash-star-is-literal',grant('literal',[rule(('*',),('customresourcedefinitions/*',),['*'])]),lambda r:False)
    add('named-settings',grant('named',[rule(('*',),('*',),['*'],['settings'])]),lambda r:app(r) and res(r) and r['name']=='settings')
    add('empty-name',grant('empty',[rule(('*',),('*',),['*'],[''])]),lambda r:app(r) and res(r) and r['name']=='')
    for verb in ['get','create','patch','deletecollection']:
        add('verb-'+verb,grant('verb',[rule(('*',),('*',),[verb])]),lambda r,v=verb:app(r) and res(r) and r['operation']==v)
    grouped=grant('operators',[rule(('*',),('*',),['*'])]);grouped[1]['subjects']=[dict(kind='Group',apiGroup='rbac.authorization.k8s.io',name='operators')]
    add('fixed-group',grouped,lambda r:r['username']=='ops' and res(r))
    add('unbound-role',grant('unbound',[rule(('*',),('*',),['*'])])[:1],lambda r:False)
    return cases


def contract_cases():
    cases=[]
    common=grant('config',[rule(('',),('configmaps',),['get'],['settings'])],'team-a')
    def add(id_,spec,items,expected='proved',failed=None,baseline=None,comparison=None,preservation=None):
        cases.append(dict(id=id_,contract=spec,snapshot=snapshot(items),expected=expected,failed=failed,
            baseline=snapshot(baseline) if baseline is not None else None,comparison=comparison,preservation=preservation))
    for group,resource,sub,_,operations in NEW_CATALOGUE:
        for operation in operations:
            names={'empty':True} if operation in ['create','deletecollection'] else ['settings']
            selected=scope(group=group,resource=resource,subresource=sub,operation=operation,namespace=None,names=names)
            spec=contract([dict(name='required-controller-access',kind='must_allow',**selected),clause('forbidden-secrets','must_not_grant',resource='secrets')])
            items=grant('controller',[rule((group,),(resource+('/'+sub if sub else ''),),[operation])])
            add(resource+'-'+(sub or 'base')+'-'+operation,spec,items)
    for group,resource in [('authorization.k8s.io','subjectaccessreviews'),('authentication.k8s.io','tokenreviews')]:
        positive=scope(group=group,resource=resource,operation='create',namespace=None,names={'empty':True})
        spec=contract([dict(name='required-review',kind='must_allow',**positive),clause('forbidden-secrets','must_not_grant',resource='secrets')])
        add(resource+'-named-rule-does-not-grant-create',spec,grant('named',[rule((group,),(resource,),['create'],['settings'])]),'violated','required-review')
        add(resource+'-local-binding-does-not-grant-create',spec,grant('local',[rule((group,),(resource,),['create'])],'team-a'),'violated','required-review')
        operator=grant('review',[rule((group,),(resource,),['create'])],subject='ops')
        for version in [9,10]:
            preserved=contract();preserved['schema_version']=version
            add(resource+'-unmentioned-v'+str(version),preserved,common+operator[:1],baseline=common+operator,comparison='proved' if version==9 else 'violated',
                preservation=None if version==9 else dict(kind=resource+'.'+group,operation='create',user='ops'))
        approved=contract(changes=[dict(positive,subject='ops')])
        add(resource+'-approved-removal',approved,common+operator[:1],baseline=common+operator,comparison='proved')
        # Approval for one review resource never permits changing the other.
        wrong=scope(group='authentication.k8s.io' if group=='authorization.k8s.io' else 'authorization.k8s.io',resource='tokenreviews' if resource=='subjectaccessreviews' else 'subjectaccessreviews',operation='create',namespace=None,names={'empty':True},subject='ops')
        add(resource+'-other-review-scope',contract(changes=[wrong]),common+operator[:1],baseline=common+operator,comparison='violated',preservation=dict(kind=resource+'.'+group,operation='create',user='ops'))
    status=grant('operator-status',[rule(('apiextensions.k8s.io',),('customresourcedefinitions/status',),['update'])],subject='ops')
    add('crd-status-unmentioned-operator',contract(),common+status[:1],baseline=common+status,comparison='violated',preservation=dict(kind='customresourcedefinitions/status.apiextensions.k8s.io',operation='update',user='ops'))
    parent_scope=scope(group='apiextensions.k8s.io',resource='customresourcedefinitions',operation='update',namespace=None,subject='ops')
    add('crd-parent-scope-not-status',contract(changes=[parent_scope]),common+status[:1],baseline=common+status,comparison='violated',preservation=dict(kind='customresourcedefinitions/status.apiextensions.k8s.io',operation='update',user='ops'))
    # Ordinary required resource and independent URL/custom preservation remain in schema 10.
    urls=grant('ops-url',[dict(verbs=['get'],nonResourceURLs=['/healthz'])],subject='ops')
    add('preserve-legacy-url',contract(),common+urls[:1],baseline=common+urls,comparison='violated',preservation=dict(kind='non_resource',operation='get',user='ops'))
    custom=grant('ops-custom',[rule(('widgets.example.test',),('widgets/status',),['update'])],'team-b',subject='ops')
    add('preserve-legacy-custom',contract(),common+custom[:1],baseline=common+custom,comparison='violated',preservation=dict(kind='widgets/status.widgets.example.test',operation='update',user='ops'))
    # Required functionality and an isolated controller prohibition distinguish valid repair from deny-all.
    forbidden=scope(group='admissionregistration.k8s.io',resource='validatingwebhookconfigurations',operation='patch',namespace=None,names=['settings'])
    fixed=contract([clause('required-config','must_allow',names=['settings']),dict(name='forbidden-webhook-patch',kind='must_not_grant',**forbidden)],changes=[forbidden])
    extra=grant('unsafe',[rule(('admissionregistration.k8s.io',),('validatingwebhookconfigurations',),['patch'],['settings'])])
    add('unsafe-webhook-patch',fixed,common+extra,'violated','forbidden-webhook-patch')
    add('valid-webhook-repair',fixed,common+extra[:1],baseline=common+extra,comparison='proved')
    add('deny-all-is-not-repair',fixed,extra[:1],'violated','required-config')
    return cases


def rejection_requests():
    rows=[]
    for group,resource,sub,_,operations in NEW_CATALOGUE:
        for op in ['apply-existing','apply-missing','update-existing','update-missing']:
            rows.append(request(group,resource,sub,op,'','settings',id_=resource+'-'+sub+'-'+op))
        sample=operations[0]
        name='' if sample=='create' else 'settings'
        rows.append(request(group,resource,sub,sample,'team-a',name,id_=resource+'-'+sub+'-namespace'))
    for group,resource in [('authorization.k8s.io','subjectaccessreviews'),('authentication.k8s.io','tokenreviews')]:
        for operation in [v for v in VERBS if v!='create']:
            rows.append(request(group,resource,operation=operation,namespace='',name='' if operation in ['list','watch','deletecollection'] else 'settings',id_=resource+'-'+operation))
        rows.append(request(group,resource,operation='create',namespace='',name='body-name',id_=resource+'-body-name'))
    for sub in ['scale','finalizers']:
        rows.append(request('apiextensions.k8s.io','customresourcedefinitions',sub,'update','','settings',id_='crd-'+sub))
    for operation in ['list','watch','create','delete','deletecollection']:
        rows.append(request('apiextensions.k8s.io','customresourcedefinitions','status',operation,'','settings',id_='crd-status-'+operation))
    return rows


def legacy_rejections():
    seen=set();rows=[]
    for row in matrix_requests():
        if not is_new(row): continue
        key=(row['apiGroup'],row['resource'],row['subresource'],row['operation'])
        if key not in seen: rows.append(row);seen.add(key)
    return rows


def expected_discovery():
    return {r+('/'+s if s else '')+'.'+g:dict(scope='Cluster',verbs=sorted(ops)) for g,r,s,_,ops in NEW_CATALOGUE}


def expected_routes():
    routes=[]
    groups=set()
    for g,r,s,_,ops in NEW_CATALOGUE:
        groups.add(g); base='/apis/'+g+'/v1/'
        if s:
            routes += [method+' '+base+r+'/{name}/'+s for method in ['GET','PUT','PATCH']]
        elif ops==['create']:
            routes.append('POST '+base+r)
        else:
            routes += [m+' '+base+r for m in ['GET','POST','DELETE']]
            routes += [m+' '+base+r+'/{name}' for m in ['GET','PUT','PATCH','DELETE']]
            routes += ['GET '+base+'watch/'+r,'GET '+base+'watch/'+r+'/{name}']
    routes += ['GET /apis/'+g+'/v1/' for g in groups]
    return sorted(routes)


def review_experiments():
    rows=[]
    for resource,group,kind in [('subjectaccessreviews','authorization.k8s.io','SubjectAccessReview'),('tokenreviews','authentication.k8s.io','TokenReview')]:
        for outcome in [True,False]:
            if resource=='subjectaccessreviews':
                spec=dict(user='reviewed-allowed' if outcome else 'reviewed-denied',groups=['body-group'],resourceAttributes=dict(group='',version='v1',resource='secrets',namespace='body-namespace',name='body-name',verb='get'))
            else:spec=dict(token='fixture-valid-token' if outcome else 'fixture-invalid-token')
            body=dict(apiVersion=group+'/v1',kind=kind,spec=spec)
            for caller in ['app','ops']:
                rows.append(dict(id=resource+'-'+str(outcome)+'-'+caller,username=caller,groups=IDENTITIES[caller],method='POST',url='/apis/'+group+'/v1/'+resource,body=json.dumps(body,sort_keys=True)))
    return rows


def review_policy():
    return snapshot(grant('reviews',[rule(('authorization.k8s.io',),('subjectaccessreviews',),['create']),rule(('authentication.k8s.io',),('tokenreviews',),['create'])]))


def audit_review(execution, rows):
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native review command failed')
    result=execution.get('data')
    require(isinstance(result,dict) and set(result)=={'schema_version','kind','valid','validation_errors','decisions'},'Wrong review response shape')
    require(type(result['schema_version']) is int and result['schema_version']==1 and result['kind']=='rbac_controller_review_authorization' and result['valid'] is True and result['validation_errors']==[],'Invalid review response')
    require(isinstance(result['decisions'],list) and len(result['decisions'])==len(rows),'Missing review decisions')
    seen=set(); expected={r['id']:r for r in rows}
    for entry in result['decisions']:
        require(isinstance(entry,dict) and set(entry)=={'id','initial','attributes','status_code','review_calls','review_attributes','authenticated_token','response'},'Wrong review entry shape')
        require(entry['id'] in expected and entry['id'] not in seen,'Review id mismatch');seen.add(entry['id'])
        row=expected[entry['id']];body=strict_json(row['body']);group=body['apiVersion'].split('/')[0]
        resource='subjectaccessreviews' if body['kind']=='SubjectAccessReview' else 'tokenreviews'
        attrs=dict(username=row['username'],groups=row['groups'],verb='create',apiGroup=group,apiVersion='v1',resource=resource,namespace='',name='',subresource='',resourceRequest=True,path=row['url'])
        require(encoded(entry['attributes'])==encoded(attrs),'Initial review caller or attributes changed')
        allowed=row['username']=='app'
        require(entry['initial']==('Allow' if allowed else 'NoOpinion') and type(entry['status_code']) is int and entry['status_code']==(201 if allowed else 403),'Initial gate/status disagreement')
        require(type(entry['review_calls']) is int and entry['review_calls']==(1 if allowed else 0),'Review handler ran before caller authorization')
        response=entry['response'];require(isinstance(response,dict),'Missing review response')
        if not allowed:
            require(entry['review_attributes'] is None and entry['authenticated_token']=='' and response.get('kind')=='Status' and response.get('reason')=='Forbidden' and response.get('code')==403,'Ungranted caller reached body review')
        elif resource=='subjectaccessreviews':
            reviewed=body['spec']; a=reviewed['resourceAttributes']
            wanted=dict(username=reviewed['user'],groups=reviewed['groups'],verb=a['verb'],apiGroup=a['group'],apiVersion=a['version'],resource=a['resource'],namespace=a['namespace'],name=a['name'],subresource='',resourceRequest=True,path='')
            require(encoded(entry['review_attributes'])==encoded(wanted) and entry['authenticated_token']=='','Reviewed body attributes were mixed with caller gate')
            status=response.get('status',{}); body_allowed=reviewed['user']=='reviewed-allowed'
            require(type(status.get('allowed')) is bool and type(status.get('denied',False)) is bool and status['allowed'] is body_allowed and status.get('denied',False) is (not body_allowed),'Wrong SAR body result')
        else:
            token=body['spec']['token'];status=response.get('status',{});body_allowed=token=='fixture-valid-token'
            require(entry['review_attributes'] is None and entry['authenticated_token']==token,'Wrong authenticated token input')
            require(type(status.get('authenticated',False)) is bool and status.get('authenticated',False) is body_allowed,'Wrong TokenReview body result')
            if body_allowed: require(status.get('user',{}).get('username')=='reviewed-token-user','Token identity was replaced by caller')
    require(seen==set(expected),'Missing review ids')


def audit_linkage(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==0,'Native linkage failed')
    value=execution.get('data')
    require(isinstance(value,dict) and set(value)=={'schema_version','kind','go_version','modules','functions','discovery','routes','allow_create_on_update'},'Wrong linkage shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_controller_native_linkage','Wrong linkage version/kind')
    require(isinstance(value['go_version'],str) and value['go_version'].startswith('go1.'),'Missing Go version')
    versions={'kubernetes':'v1.34.0','apiserver':'v0.34.0','apiextensions-apiserver':'v0.34.0','api':'v0.34.0','apimachinery':'v0.34.0'}
    require(isinstance(value['modules'],dict),'Missing compiled modules')
    for m,v in versions.items():require(value['modules'].get('k8s.io/'+m)==v,'Wrong compiled module '+m)
    require(encoded(value['discovery'])==encoded(expected_discovery()),'Native installer scope/verbs differ')
    require(value['routes']==expected_routes(),'Native installer route inventory differs')
    require(encoded(value['allow_create_on_update'])==encoded({k:False for k in ['validatingwebhookconfigurations','mutatingwebhookconfigurations','customresourcedefinitions','customresourcedefinitions/status']}),'Unexpected native PUT creation')
    require(isinstance(value['functions'],dict) and set(value['functions'])==set(LINKAGE),'Native function inventory mismatch')
    for label,(module,source,line,function) in LINKAGE.items():
        entry=value['functions'][label]
        require(isinstance(entry,dict) and set(entry)=={'file','line','function'},'Wrong function shape')
        require(entry['function']=='k8s.io/'+module+'/'+function and type(entry['line']) is int and entry['line'] in [line,line+1],'Wrong native linked function '+label)
        require(isinstance(entry['file'],str) and entry['file'].endswith('k8s.io/'+module+'@'+versions[module]+'/'+source),'Wrong linked source '+label)
    return value


def audit_report(execution,spec,expected,comparison=False):
    value=execution.get('data'); version=spec['schema_version']
    require(isinstance(value,dict) and value.get('result')==expected and type(execution.get('returncode')) is int and execution['returncode']==EXIT_CODES[expected],'Wrong verdict/exit')
    require(type(value.get('schema_version')) is int and value['schema_version']==10,'Wrong report schema')
    require(value.get('property')==('rbac-repair-preservation' if comparison else 'kubernetes-rbac-access'),'Wrong property')
    require(value.get('assurance')==dict(profile=PROFILE if version==10 else coverage.PROFILE,status='within_profile',findings=[]),'Wrong assurance')
    frozen=value.get('frozen_spec')
    require(isinstance(frozen,dict) and type(frozen.get('schema_version')) is int and frozen['schema_version']==version and frozen.get('kind')==spec['kind'] and isinstance(frozen.get('canonical'),str),'Missing frozen identity')
    require(encoded(coverage.normalized_contract(strict_json(frozen['canonical'])))==encoded(coverage.normalized_contract(spec)),'Frozen contract changed')
    if expected!='violated':require(value.get('counterexample') is None,'Unexpected witness')
    if expected=='proved':require(value.get('clause') is None,'Unexpected clause')
    return value


def witness_request(report,spec):
    witness=report.get('counterexample');require(isinstance(witness,dict) and 'object_request' in witness,'Missing typed witness')
    obj=witness['object_request']
    if obj is None:
        row=dict(id='witness',username=witness.get('principal'),groups=witness.get('identity_groups'),operation=witness.get('action'),resourceRequest=False,path=witness.get('path'))
    else:
        require(isinstance(obj,dict) and set(obj)=={'namespace','name','resource_kind'} and obj['resource_kind'] in KINDS,'Invalid witness coordinates/kind')
        g,r,s,_=KINDS[obj['resource_kind']]
        row=dict(id='witness',username=witness.get('principal'),groups=witness.get('identity_groups'),operation=witness.get('action'),apiGroup=g,resource=r,subresource=s,namespace=obj['namespace'],name=obj['name'],resourceRequest=True)
    validate_request(row,{i['username']:i['groups'] for i in spec['context']['identities']},spec['custom_resources'])
    require(strings(witness.get('granting_rules'),nonempty=True) and len(set(witness['granting_rules']))==len(witness['granting_rules']),'Invalid grant evidence')
    return row


def audit_witness(report,case,comparison=False):
    row=witness_request(report,case['contract']);selected=report.get('clause');require(isinstance(selected,dict),'Missing clause')
    if comparison:
        require(selected.get('kind')=='must_preserve' and selected.get('name')=='preservation-outside-change-scope','Wrong preservation obligation')
        require(not any(scope_matches(s,row) for s in case['contract']['change_scope']),'Witness inside approved scope')
        wanted=case['preservation'];kind=report['counterexample']['object_request']['resource_kind'] if row['resourceRequest'] else 'non_resource'
        require(kind==wanted['kind'] and row['operation']==wanted['operation'] and row['username']==wanted['user'],'Wrong preservation dimensions')
    else:
        clauses=[c for c in case['contract']['clauses'] if c['name']==selected.get('name')]
        require(len(clauses)==1 and clauses[0]['name']==case['failed'] and clauses[0]['kind']==selected.get('kind') and scope_matches(clauses[0],row),'Witness outside failed clause')
    return row


def planned_inputs():
    inputs={'contract.json':encoded(contract()),'legacy-contract.json':encoded(coverage.contract()),'catalogue.json':encoded(NEW_CATALOGUE),
        'matrix/requests.json':encoded(matrix_requests()),'matrix/urls.json':encoded([as_url(r) for r in matrix_requests()]),
        'rejections/requests.json':encoded(rejection_requests()),'rejections/legacy.json':encoded(legacy_rejections()),
        'native-linkage.json':encoded(LINKAGE),'native-discovery.json':encoded(expected_discovery()),'native-routes.json':encoded(expected_routes()),
        'reviews/requests.json':encoded(review_experiments()),'reviews/snapshot.json':encoded(review_policy())}
    for c in matrix_cases():
        for key in ['snapshot','expected']:inputs['matrix/'+c['id']+'/'+key+'.json']=encoded(c[key])
    for c in contract_cases():
        for key in ['contract','snapshot','baseline']:
            if c[key] is not None:inputs['contracts/'+c['id']+'/'+key+'.json']=encoded(c[key])
        inputs['contracts/'+c['id']+'/expected.json']=encoded({k:c[k] for k in ['expected','failed','comparison','preservation']})
    return inputs


def source_provenance(module_metadata):
    metadata=read_json(module_metadata);kube=Path(metadata['Dir']);roots={'kubernetes':kube,'apiserver':kube.parent/'apiserver@v0.34.0','apiextensions-apiserver':kube.parent/'apiextensions-apiserver@v0.34.0'}
    pins=read_json(HERE/'source-pins.json');require(set(pins)==set(SOURCE_FILES),'Wrong source modules');result={}
    for module,entries in pins.items():
        require(set(entries)==set(SOURCE_FILES[module]),'Wrong source inventory')
        for relative,sha in entries.items():
            require(not Path(relative).is_absolute() and '..' not in Path(relative).parts,'Unsafe source path')
            path=roots[module]/relative;require(digest(path)==sha,'Upstream source changed: '+str(path));result[str(path)]=sha
    return result


def finite_rows(case):
    return [r for r in matrix_requests() if case['contract']['schema_version']==10 or not is_new(r)]


def planned_counts(native_only=False):
    cases=contract_cases()
    return dict(matrix_comparisons=len(matrix_requests())*len(matrix_cases()),
        contract_native_checks=sum(len(finite_rows(c))*(2 if c['baseline'] is not None else 1) for c in cases),
        review_handler_checks=len(review_experiments()),
        rejected_requests=0 if native_only else len(rejection_requests()),
        legacy_rejected_requests=0 if native_only else len(legacy_rejections()),
        contract_witness_replays=0 if native_only else sum(c['expected']=='violated' for c in cases),
        preservation_witness_replays=0 if native_only else sum(c['comparison']=='violated' for c in cases))


def audit_completion(result,native_only=False):
    require(result.get('failures')==[] and result.get('native_only') is native_only,'Wrong completion mode/failures')
    for key,want in planned_counts(native_only).items():require(type(result.get(key)) is int and result[key]==want,'Incomplete counter '+key)
    expected={'matrix/'+c['id']:dict(matrix_comparisons=len(matrix_requests())) for c in matrix_cases()}
    for c in contract_cases():
        entry=dict(native_contract=c['expected'],native_comparison=c['comparison'])
        if not native_only:
            entry['contract']=c['expected']
            if c['baseline'] is not None:entry['comparison']=c['comparison']
        expected['contracts/'+c['id']]=entry
    require(encoded(result.get('cases'))==encoded(expected),'Incomplete case inventory')
    for key in ['inputs_unchanged','binaries_unchanged','native_linkage_verified']:
        require(result.get(key) is True,'Missing provenance check '+key)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ['reference','module-metadata','output']:parser.add_argument('--'+key,type=Path,required=True)
    for key in ['model','soundcheck']:parser.add_argument('--'+key,type=Path)
    parser.add_argument('--z3',default='z3');parser.add_argument('--native-only',action='store_true');args=parser.parse_args(argv)
    for key,value in vars(args).items():
        if isinstance(value,Path):setattr(args,key,value.resolve())
    result=dict(complete=False,profile=PROFILE,native_only=args.native_only,cases={},failures=[],input_sha256={},**{k:0 for k in planned_counts()},limits=[
        'Synthetic source-derived expectations, not owner-reviewed requirements or a deployed-cluster evaluation.',
        'Initial caller RBAC only; review-body authorization/authentication results are distinct and are not verified by Soundcheck.',
        'Native installer discovery uses the real REST types and strategies with fixture object factories, without storage or a live cluster.',
        'Body validity, admission, successful effects, CRD lifecycle, webhook behavior and privilege transitions remain outside the model.',
        'NoOpinion is not final denial under other authorizers; finite conformance is not a universal model-correctness proof.'])
    save(args.output,result)
    try:
        result['reference']=module_provenance(args.module_metadata);result['upstream_source_sha256']=source_provenance(args.module_metadata)
        inputs=planned_inputs();audit_pins(inputs,read_json(HERE/'inputs.json'))
        require((HERE/'contract.json').read_bytes()==inputs['contract.json'],'Runnable contract differs')
        artifacts=args.output.parent/'artifacts'
        for key,value in inputs.items():
            path=artifacts/key;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value);result['input_sha256'][str(path)]=digest(path)
        source_dir=Path(__file__).resolve().parent
        paths=[Path(__file__),HERE/'generate.py',HERE/'inputs.json',HERE/'contract.json',HERE/'source-pins.json',args.module_metadata,source_dir/'test_controller_apis_runner.py']
        paths += sorted(source_dir.glob('run*.py'))+sorted((source_dir/'oracle').glob('*.go'))+[source_dir/'oracle/go.mod',source_dir/'oracle/go.sum',source_dir/'oracle/module-pins.json']
        result['source_sha256']={str(p):digest(p) for p in paths}
        binaries=[args.reference];z3=None
        if not args.native_only:
            require(args.model is not None and args.soundcheck is not None,'Full comparison requires model and CLI')
            z3=shutil.which(args.z3);require(z3 is not None,'Z3 required');binaries += [args.model,args.soundcheck,Path(z3)]
        result['binary_sha256']={str(p):digest(p) for p in binaries};save(args.output.parent/'before-execution.json',result)
        with tempfile.TemporaryDirectory(prefix='soundcheck-controller-z3-') as temporary:
            environment=dict(os.environ)
            if z3 is not None:
                Path(temporary,'z3').symlink_to(Path(z3).resolve());environment['PATH']=temporary+os.pathsep+environment.get('PATH','')
            result['native_linkage']=audit_linkage(execute([args.reference,'--controller-reference-info'],args.output.parent/'native-linkage.json',environment));result['native_linkage_verified']=True
            audit_review(execute([args.reference,'--controller-review-reference',artifacts/'reviews/snapshot.json',artifacts/'reviews/requests.json'],artifacts/'reviews/result.json',environment),review_experiments())
            result['review_handler_checks']=len(review_experiments())
            def native(manifest,rows,folder,label,expected=None):
                path=folder/(label+'-urls.json');save(path,[as_url(r) for r in rows])
                execution=execute([args.reference,'--coverage-urls',manifest,path],folder/(label+'-native.json'),environment)
                return coverage.audit_native_urls(execution,rows,expected)
            def agree(manifest,spec_path,rows,folder,label,expected=None):
                spec=read_json(spec_path)
                for row in rows:validate_request(row,custom=spec['custom_resources'])
                observed=native(manifest,rows,folder,label,expected)
                if not args.native_only:
                    path=folder/(label+'-requests.json');save(path,rows)
                    model=execute([args.model,manifest,spec_path,path],folder/(label+'-model.json'),environment)
                    concrete=decisions(model,rows,'model');symbolic=smt_decisions(model,rows,folder,label,z3,environment)
                    require(observed==concrete==symbolic,'Native/concrete/SMT mismatch '+label)
                return observed
            rows=matrix_requests()
            for row in rows:validate_request(row)
            for case in matrix_cases():
                folder=artifacts/'matrix'/case['id'];agree(folder/'snapshot.json',artifacts/'contract.json',rows,folder,'matrix',case['expected'])
                result['matrix_comparisons']+=len(rows);result['cases']['matrix/'+case['id']]=dict(matrix_comparisons=len(rows));save(args.output,result)
                print(case['id']+': frozen/native'+('' if args.native_only else '/concrete/SMT')+' agree',flush=True)
            for case in contract_cases():
                folder=artifacts/'contracts'/case['id'];manifest=folder/'snapshot.json';spec_path=folder/'contract.json';spec=case['contract'];selected_rows=finite_rows(case)
                observed=native(manifest,selected_rows,folder,'finite');failed=[]
                for selected in spec['clauses']:
                    points=[r for r in selected_rows if scope_matches(selected,r)];require(points,'Uninhabited finite clause '+case['id']+'/'+selected['name'])
                    wanted='Allow' if selected['kind']=='must_allow' else 'NoOpinion'
                    if any(observed[r['id']]!=wanted for r in points):failed.append(selected['name'])
                require(bool(failed)==(case['expected']=='violated'),'Native contract differs '+case['id'])
                if failed:require(failed[0]==case['failed'],'Wrong failed native clause '+case['id'])
                result['contract_native_checks']+=len(selected_rows)
                if case['baseline'] is not None:
                    before=native(folder/'baseline.json',selected_rows,folder,'finite-before')
                    changed=[r for r in selected_rows if before[r['id']]!=observed[r['id']] and not any(scope_matches(s,r) for s in spec['change_scope'])]
                    require(bool(changed)==(case['comparison']=='violated'),'Native preservation differs '+case['id']);result['contract_native_checks']+=len(selected_rows)
                def replay(report,comparison=False):
                    row=audit_witness(report,case,comparison)
                    after=agree(manifest,spec_path,[row],folder,'witness-after')['witness']
                    require(bool(report['counterexample']['granting_rules'])==(after=='Allow'),'Grant evidence contradicts native decision')
                    if comparison:
                        before=agree(folder/'baseline.json',spec_path,[row],folder,'witness-before')['witness'];require(before!=after,'No native preservation change');result['preservation_witness_replays']+=1
                    else:
                        require(after==('Allow' if report['clause']['kind']=='must_not_grant' else 'NoOpinion'),'Witness does not violate clause');result['contract_witness_replays']+=1
                entry=dict(native_contract=case['expected'],native_comparison=case['comparison'])
                if not args.native_only:
                    report=audit_report(execute([args.soundcheck,'rbac','verify',manifest,'--contract',spec_path,'--format','json'],folder/'verify.json',environment),spec,case['expected']);entry['contract']=report['result']
                    if report['result']=='violated':replay(report)
                    if case['baseline'] is not None:
                        report=audit_report(execute([args.soundcheck,'rbac','compare',folder/'baseline.json',manifest,'--contract',spec_path,'--format','json'],folder/'compare.json',environment),spec,case['comparison'],True);entry['comparison']=report['result']
                        if report['result']=='violated':replay(report,True)
                result['cases']['contracts/'+case['id']]=entry;save(args.output,result)
                print(case['id']+': native requirements/preservation checked',flush=True)
            if not args.native_only:
                for category,rejected,spec_path,counter in [('outside',rejection_requests(),artifacts/'contract.json','rejected_requests'),('legacy',legacy_rejections(),artifacts/'legacy-contract.json','legacy_rejected_requests')]:
                    for i,row in enumerate(rejected):
                        label=category+'-'+str(i);path=artifacts/'rejections'/(label+'.json');save(path,[row])
                        model=execute([args.model,artifacts/'matrix/all-resource-grants/snapshot.json',spec_path,path],artifacts/'rejections'/(label+'-model.json'),environment)
                        require(decisions(model,[row],'model',allow_unsupported=True) is None,'Outside-domain decision '+label);result[counter]+=1
            for key in ['input_sha256','source_sha256','binary_sha256','upstream_source_sha256']:
                require(all(digest(Path(path))==sha for path,sha in result[key].items()),key+' changed during execution')
            audit_pins(planned_inputs(),read_json(HERE/'inputs.json'));result.update(inputs_unchanged=True,binaries_unchanged=True)
            audit_completion(result,args.native_only);result['complete']=True
    except (OSError,RuntimeError,ValueError,KeyError,TypeError) as error:result['failures'].append(str(error))
    save(args.output,result)
    print({key:result[key] for key in ['complete','native_only']+list(planned_counts())+['failures']})
    return 0 if result['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
