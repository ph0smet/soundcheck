#!/usr/bin/env python3
"""Independent Kubernetes v1.34 policy-change guard and composed gate acceptance."""
import argparse
import copy
import hashlib
import itertools
import json
import os
import shutil
import tempfile
from pathlib import Path
from urllib.parse import quote

from run import digest, execute, module_provenance, read_json, require, save, strict_json
from run_resources import encoded, audit_pins
import run_controller_apis as controller

HERE = Path(__file__).resolve().parent.parent / 'policy-changes'
GROUP = 'rbac.authorization.k8s.io'
RESOURCES = {'Role': 'roles', 'ClusterRole': 'clusterroles',
             'RoleBinding': 'rolebindings', 'ClusterRoleBinding': 'clusterrolebindings'}
IDENTITIES = [{'username': 'app', 'groups': []}, {'username': 'ops', 'groups': ['operators']},
              {'username': 'deployer', 'groups': ['deployers']}]
SOURCE_FILES = {
    'kubernetes': [
        'pkg/registry/rbac/escalation_check.go', 'pkg/registry/rbac/helpers.go',
        'pkg/registry/rbac/validation/rule.go', 'pkg/registry/rbac/validation/internal_version_adapter.go',
        'pkg/apis/rbac/validation/validation.go', 'pkg/apis/rbac/v1/defaults.go',
        'pkg/registry/rbac/rest/storage_rbac.go', 'pkg/kubeapiserver/authorizer/reload.go',
        'plugin/pkg/auth/authorizer/rbac/rbac.go',
        *[f'pkg/registry/rbac/{kind}/{file}' for kind in ['role', 'clusterrole', 'rolebinding', 'clusterrolebinding']
          for file in ['policybased/storage.go', 'strategy.go']]],
    'apiserver': ['pkg/endpoints/request/requestinfo.go', 'pkg/endpoints/filters/requestinfo.go',
                  'pkg/endpoints/filters/authorization.go', 'pkg/endpoints/handlers/update.go',
                  'pkg/registry/rest/update.go', 'pkg/registry/generic/registry/store.go',
                  'pkg/authorization/authorizerfactory/builtin.go'],
    'component-helpers': ['auth/rbac/validation/policy_comparator.go'],
}
LINKAGE = {
    'request-info': ('apiserver', 'pkg/endpoints/filters/requestinfo.go', 28, 'pkg/endpoints/filters.WithRequestInfo'),
    'request-classifier': ('apiserver', 'pkg/endpoints/request/requestinfo.go', 129, 'pkg/endpoints/request.(*RequestInfoFactory).NewRequestInfo'),
    'authorization-filter': ('apiserver', 'pkg/endpoints/filters/authorization.go', 53, 'pkg/endpoints/filters.WithAuthorization'),
    'authorizer-attributes': ('apiserver', 'pkg/endpoints/filters/authorization.go', 101, 'pkg/endpoints/filters.GetAuthorizerAttributes'),
    'rbac-authorizer': ('kubernetes', 'plugin/pkg/auth/authorizer/rbac/rbac.go', 75, 'plugin/pkg/auth/authorizer/rbac.(*RBACAuthorizer).Authorize'),
    'role-escalation': ('kubernetes', 'pkg/registry/rbac/escalation_check.go', 55, 'pkg/registry/rbac.RoleEscalationAuthorized'),
    'binding-authorization': ('kubernetes', 'pkg/registry/rbac/escalation_check.go', 101, 'pkg/registry/rbac.BindingAuthorized'),
    'superuser': ('kubernetes', 'pkg/registry/rbac/escalation_check.go', 32, 'pkg/registry/rbac.EscalationAllowed'),
    'gc-fields': ('kubernetes', 'pkg/registry/rbac/helpers.go', 29, 'pkg/registry/rbac.IsOnlyMutatingGCFields'),
    'rules-for': ('kubernetes', 'pkg/registry/rbac/validation/rule.go', 118, 'pkg/registry/rbac/validation.(*DefaultRuleResolver).RulesFor'),
    'role-reference': ('kubernetes', 'pkg/registry/rbac/validation/rule.go', 240, 'pkg/registry/rbac/validation.(*DefaultRuleResolver).GetRoleReferenceRules'),
    'confirm-no-escalation': ('kubernetes', 'pkg/registry/rbac/validation/rule.go', 53, 'pkg/registry/rbac/validation.ConfirmNoEscalation'),
    'covers': ('component-helpers', 'auth/rbac/validation/policy_comparator.go', 27, 'auth/rbac/validation.Covers'),
}
for _kind, _create, _update in [('role', 67, 80), ('clusterrole', 73, 93), ('rolebinding', 70, 102), ('clusterrolebinding', 69, 94)]:
    for _method, _line in [('create', _create), ('update', _update)]:
        LINKAGE[_kind+'-'+_method] = ('kubernetes', f'pkg/registry/rbac/{_kind}/policybased/storage.go', _line,
                                    f'pkg/registry/rbac/{_kind}/policybased.(*Storage).{_method.title()}')


def rule(verbs=('get',), groups=('',), resources=('configmaps',), names=None, urls=None):
    result = {'verbs': list(verbs)}
    if urls is not None:
        result['nonResourceURLs'] = list(urls)
    else:
        result.update(apiGroups=list(groups), resources=list(resources))
        if names is not None:
            result['resourceNames'] = list(names)
    return result


def role(kind, name, namespace=None, rules=()):
    metadata = {'name': name}
    if namespace is not None:
        metadata['namespace'] = namespace
    return dict(apiVersion=GROUP+'/v1', kind=kind, metadata=metadata, rules=copy.deepcopy(list(rules)))


def binding(kind, name, namespace=None, role_kind='ClusterRole', role_name='referenced', subject='recipient', subject_kind='User'):
    metadata = {'name': name}
    if namespace is not None:
        metadata['namespace'] = namespace
    return dict(apiVersion=GROUP+'/v1', kind=kind, metadata=metadata,
                roleRef=dict(apiGroup=GROUP, kind=role_kind, name=role_name),
                subjects=[dict(apiGroup=GROUP, kind=subject_kind, name=subject)])


def authority(rules, namespace=None, name='actor-authority', subject='deployer', subject_kind='User'):
    return [role('ClusterRole', name, rules=rules),
            binding('ClusterRoleBinding' if namespace is None else 'RoleBinding', name, namespace,
                    role_name=name, subject=subject, subject_kind=subject_kind)]


def snapshot(items):
    return dict(apiVersion='v1', kind='List', items=copy.deepcopy(items))


def contract(kind, operation, name='target', namespace=None, requirements=None):
    requirements = copy.deepcopy(requirements or controller.contract())
    requirements['context']['identities'] = copy.deepcopy(IDENTITIES)
    return dict(schema_version=1, kind='kubernetes-rbac-policy-change', actor='deployer', operation=operation,
                target=dict(kind=kind, namespace=namespace, name=name), requirements=requirements)


def common():
    return [role('Role', 'required-config', 'team-a', [rule(names=['settings'])]),
            binding('RoleBinding', 'required-config', 'team-a', 'Role', 'required-config', 'app')]


def atoms(rules):
    """Literal obligation expansion only; this function never decides coverage."""
    result = []
    for selected in rules:
        if selected.get('nonResourceURLs'):
            result += [rule([verb], urls=[path]) for path in selected['nonResourceURLs'] for verb in selected['verbs']]
        else:
            for group, resource, verb, name in itertools.product(selected['apiGroups'], selected['resources'], selected['verbs'], selected.get('resourceNames') or [None]):
                result.append(rule([verb], [group], [resource], None if name is None else [name]))
    return result


def cases():
    result = []
    future = rule(['frobnicate'], ['future.example.test'], ['novelresources/arbitrary'], ['one', 'two'])

    def add(id_, kind='Role', operation='create', required=None, owner=None, initial=True,
            initial_names=None, special=False, special_names=None, covered=False, missing=None,
            authority_namespace=None, role_kind=None, subject='deployer', subject_kind='User',
            effective_owner=True, extra=(), name='target', required_result='proved'):
        required = copy.deepcopy([future] if required is None else required)
        owner = copy.deepcopy([] if owner is None else owner)
        namespace = 'team-a' if kind in ['Role', 'RoleBinding'] else None
        verb = 'create' if operation == 'create' else 'update'
        initial_rule = rule([verb], [GROUP], [RESOURCES[kind]], initial_names)
        special_verb = 'bind' if kind.endswith('Binding') else 'escalate'
        referenced_kind = role_kind or 'ClusterRole'
        special_resource = RESOURCES[referenced_kind] if kind.endswith('Binding') else RESOURCES[kind]
        special_name = 'referenced' if kind.endswith('Binding') else ('' if operation == 'create' else name)
        if special:
            owner.append(rule([special_verb], [GROUP], [special_resource], [special_name] if special_names is None else special_names))
        if initial:
            owner.insert(0, initial_rule)
        baseline = common() + authority(owner, authority_namespace, subject=subject, subject_kind=subject_kind) + copy.deepcopy(list(extra))
        if kind.endswith('Binding'):
            baseline.append(role(referenced_kind, 'referenced', namespace if referenced_kind == 'Role' else None, required))
            next_object = binding(kind, name, namespace, referenced_kind, 'referenced')
            old_object = binding(kind, name, namespace, referenced_kind, 'referenced', 'old-recipient')
        else:
            next_object = role(kind, name, namespace, required)
            old_object = role(kind, name, namespace, [])
            if not required:
                old_object['rules'] = [future]
        after = baseline + [next_object]
        before = baseline + ([old_object] if operation == 'update-existing' else [])
        initial_allowed = initial and effective_owner and (authority_namespace is None or authority_namespace == namespace)
        if initial_names is not None:
            initial_allowed = initial_allowed and ('' if operation == 'create' else name) in initial_names
        special_allowed = initial_allowed and special and effective_owner and (authority_namespace is None or authority_namespace == namespace) and special_name in ([special_name] if special_names is None else special_names)
        use_coverage = initial_allowed and not special_allowed
        accepted = initial_allowed and (special_allowed or covered)
        expected = dict(initial='Allow' if initial_allowed else 'NoOpinion',
                        special=None if not initial_allowed else ('Allow' if special_allowed else 'NoOpinion'),
                        accepted=accepted, covered=covered if use_coverage else None,
                        owner_rules=owner if use_coverage else [], required_rules=required if use_coverage else [],
                        missing_rules=[] if not use_coverage or covered else atoms(required) if missing is None else missing,
                        result=required_result if accepted else 'violated', stage='access' if accepted else 'authorization')
        result.append(dict(id=id_, before=snapshot(before), after=snapshot(after),
                           contract=contract(kind, operation, name, namespace), expected=expected))
        return result[-1]

    for kind in RESOURCES:
        for operation in ['create', 'update-existing']:
            prefix=kind.lower()+'-'+operation
            add(prefix+'-initial-not-granted', kind, operation, initial=False)
            add(prefix+'-uncovered-future-policy', kind, operation)
            add(prefix+'-covered-future-policy', kind, operation, owner=[future], covered=True)
            add(prefix+'-explicit-special', kind, operation, special=True)
            add(prefix+'-empty-policy', kind, operation, required=[], covered=True)
            add(prefix+'-named-initial', kind, operation, initial_names=['target'], owner=[future], covered=True)
    for kind in ['Role', 'ClusterRole']:
        add(kind.lower()+'-named-escalate-does-not-authorize-post', kind, special=True, special_names=['target'])
        add(kind.lower()+'-empty-escalate-does-not-authorize-put', kind, 'update-existing', special=True, special_names=[''])
        add(kind.lower()+'-special-without-initial', kind, initial=False, special=True)
    for kind in ['RoleBinding', 'ClusterRoleBinding']:
        add(kind.lower()+'-bind-targets-role-not-binding', kind, special=True, special_names=['target'])
        add(kind.lower()+'-bind-without-initial', kind, initial=False, special=True)
    add('rolebinding-local-clusterrole-bind', 'RoleBinding', special=True, authority_namespace='team-a')
    add('rolebinding-local-role-bind', 'RoleBinding', special=True, authority_namespace='team-a', role_kind='Role')
    add('clusterrolebinding-local-authority-is-irrelevant', 'ClusterRoleBinding', special=True, authority_namespace='team-a')
    add('role-wrong-namespace-authority', authority_namespace='team-b', owner=[future], covered=True)
    add('role-group-authority', owner=[future], subject='deployers', subject_kind='Group', covered=True)
    add('role-wrong-group-authority', owner=[future], subject='other-group', subject_kind='Group', effective_owner=False)
    sa=add('serviceaccount-actor-local-binding', owner=[future], authority_namespace='team-a', covered=True)
    sa_name='system:serviceaccount:team-a:deployer'
    sa['contract']['actor']=sa_name
    sa['contract']['requirements']['context']['identities'][-1]={'username':sa_name,'groups':['system:serviceaccounts','system:serviceaccounts:team-a','system:authenticated']}
    for state in ['before','after']:
        sa[state]['items'][3]['subjects']=[dict(kind='ServiceAccount',name='deployer')]
    add('unbound-role-is-not-owner-authority', extra=[role('ClusterRole','unbound-future',rules=[future])])
    aggregate=role('ClusterRole','aggregated-owner',rules=[future])
    aggregate['aggregationRule']={'clusterRoleSelectors':[{'matchLabels':{'aggregate':'yes'}}]}
    contributor=role('ClusterRole','contributor',rules=[future]);contributor['metadata']['labels']={'aggregate':'yes'}
    aggregated=add('resolved-baseline-aggregate-owner',covered=True,extra=[aggregate,contributor,binding('ClusterRoleBinding','aggregated-owner',role_name='aggregated-owner',subject='deployer')])
    aggregated['expected']['owner_rules'].append(copy.deepcopy(future))
    # Arbitrary policy strings are checked without a resource/verb catalogue.
    add('target-wildcard-not-covered-by-enumeration', required=[rule(['*'], ['future.test'], ['gadgets'])], owner=[rule(['get','list','watch','create','update','patch','delete','deletecollection'], ['future.test'], ['gadgets'])])
    add('target-group-wildcard-not-covered-by-known-groups', required=[rule(groups=['*'])], owner=[rule(groups=['','apps','batch','future.test'])])
    add('target-resource-wildcard-not-covered-by-known-resources', required=[rule(resources=['*'])], owner=[rule(resources=['configmaps','secrets','pods'])])
    add('owner-universal-covers-arbitrary-policy', required=[future], owner=[rule(['*'], ['*'], ['*/arbitrary'])], covered=True)
    add('owner-parent-star-is-literal', required=[future], owner=[rule(['*'], ['*'], ['novelresources/*'])])
    add('owner-named-cannot-cover-all-names', required=[rule()], owner=[rule(names=['one','two'])])
    add('owner-all-names-covers-literal-star-name', required=[rule(names=['*'])], owner=[rule()], covered=True)
    add('owner-star-name-is-literal', required=[rule(names=['one'])], owner=[rule(names=['*'])])
    add('split-owner-rules-cover-one-cross-product', required=[rule(['get','list'], resources=['pods','secrets'], names=['one','two'])],
        owner=[rule([verb], resources=[resource], names=[name]) for verb,resource,name in itertools.product(['get','list'],['pods','secrets'],['one','two'])], covered=True)
    missing=rule(['list'], resources=['secrets'], names=['two'])
    add('one-uncovered-atomic-permission', required=[rule(['get','list'], resources=['pods','secrets'], names=['one','two'])],
        owner=[rule([verb], resources=[resource], names=[name]) for verb,resource,name in itertools.product(['get','list'],['pods','secrets'],['one','two']) if (verb,resource,name)!=('list','secrets','two')], missing=[missing])
    for id_, required, owner, covered in [
        ('url-prefix-covers', '/api/v1', '/api*', True), ('url-exact-does-not-cover-pattern', '/api*', '/api', False),
        ('url-trailing-stars-native-prefix', '/api/v1', '/api***', True), ('url-middle-star-literal', '/api/v1', '/a*i*', False),
        ('url-wildcard-covers-future-path', '/future/unknown', '*', True), ('url-verb-wildcard-not-enumerated', '/api', '/api', False)]:
        add(id_, 'ClusterRole', required=[rule(['*'] if id_=='url-verb-wildcard-not-enumerated' else ['get'], urls=[required])],
            owner=[rule(['get'], urls=[owner])], covered=covered)
    add('resource-authority-does-not-cover-url', 'ClusterRole', required=[rule(urls=['/metrics'])], owner=[rule(['*'],['*'],['*'])], covered=True)
    # A resource wildcard includes escalate; explicitly remove that bypass by
    # restricting the owner rule to the core group for the actual coverage test.
    result[-1]['id']='resource-wildcard-explicit-escalate-bypass'
    result[-1]['expected'].update(special='Allow', covered=None, owner_rules=[], required_rules=[], missing_rules=[])
    add('core-resource-authority-does-not-cover-url', 'ClusterRole', required=[rule(urls=['/metrics'])], owner=[rule(['*'],[''],['*'])])
    add('url-authority-does-not-cover-resource', 'ClusterRole', required=[future], owner=[rule(['*'],urls=['*'])])
    add('rbac-colon-target-name', 'Role', 'update-existing', name='system:controller:fixture', owner=[future], covered=True)

    # Candidate authority is never used to authorize its own insertion.
    self_edit=add('self-edit-cannot-introduce-escalate', 'ClusterRole', 'update-existing', required=[future])
    before_items=self_edit['before']['items']; after_items=self_edit['after']['items']
    before_items[-1]['metadata']['name']='actor-authority'
    before_items[-1]['rules']=copy.deepcopy(before_items[2]['rules'])
    after_items[-1]['metadata']['name']='actor-authority'
    after_items[-1]['rules']=copy.deepcopy(before_items[2]['rules'])+[rule(['escalate'],[GROUP],['clusterroles'],['actor-authority']),future]
    del before_items[2]; del after_items[2]
    self_edit['contract']['target']['name']='actor-authority'
    self_edit['expected']['required_rules']=copy.deepcopy(after_items[-1]['rules'])
    self_edit['expected']['missing_rules']=atoms(after_items[-1]['rules'][1:])

    # Authorized target writes still have to satisfy the frozen access contract
    # and preserve permissions outside its separately approved change scope.
    for id_, recipient, permission, approved, outcome, stage in [
        ('authorized-binding-violates-access', 'app', rule(resources=['secrets']), False, 'violated', 'access'),
        ('authorized-binding-loses-preservation', 'ops', rule(resources=['configmaps'],names=['settings']), False, 'violated', 'preservation'),
        ('authorized-binding-approved-scope', 'app', rule(resources=['pods'],names=['settings']), True, 'proved', 'access'),
        ('authorized-binding-unapproved-scope', 'app', rule(resources=['pods'],names=['settings']), False, 'violated', 'preservation')]:
        selected=add(id_, 'RoleBinding', required=[permission], special=True, required_result=outcome)
        selected['after']['items'][-1]['subjects'][0]['name']=recipient
        if approved:
            selected['contract']['requirements']['change_scope']=[controller.scope(resource='pods',namespace='team-a',names=['settings'])]
        selected['expected']['stage']=stage
    require(len({case['id'] for case in result})==len(result), 'Duplicate policy-change case id')
    return result


def initial_attributes(case):
    spec=case['contract']; target=spec['target']; namespace=target['namespace'] or ''
    operation=spec['operation']; name='' if operation=='create' else target['name']
    path='/apis/'+GROUP+'/v1'
    if namespace:
        path+='/namespaces/'+quote(namespace, safe='')
    path+='/'+RESOURCES[target['kind']]
    if operation!='create':
        path+='/'+quote(name,safe=':')
    identity=next(i for i in spec['requirements']['context']['identities'] if i['username']==spec['actor'])
    return dict(username=spec['actor'],groups=identity['groups'],verb='create' if operation=='create' else 'update',
                apiGroup=GROUP,apiVersion='v1',resource=RESOURCES[target['kind']],namespace=namespace,name=name,
                subresource='',resourceRequest=True,path=path)


def target_object(case):
    target=case['contract']['target']
    return next(obj for obj in case['after']['items'] if obj['kind']==target['kind'] and obj['metadata']['name']==target['name'] and obj['metadata'].get('namespace','')==(target['namespace'] or ''))


def special_attributes(case):
    attrs=initial_attributes(case)
    attrs.update(apiVersion='*',path='',verb='escalate')
    obj=target_object(case)
    if obj['kind'].endswith('Binding'):
        attrs.update(verb='bind',resource=RESOURCES[obj['roleRef']['kind']],name=obj['roleRef']['name'])
    return attrs


def eligible_rules(case):
    """Audit native operand provenance from literal frozen bindings and roles.

    This selects supplied rules; it neither interprets permissions nor decides
    whether an actor can grant a proposed policy.
    """
    attrs=initial_attributes(case);items=case['before']['items']
    roles={(obj['kind'],obj['metadata'].get('namespace',''),obj['metadata']['name']):obj
           for obj in items if obj['kind'] in ['Role','ClusterRole']}
    bindings=[obj for obj in items if obj['kind']=='ClusterRoleBinding']
    if attrs['namespace']:
        bindings += [obj for obj in items if obj['kind']=='RoleBinding' and obj['metadata']['namespace']==attrs['namespace']]
    result=[]
    for selected in bindings:
        namespace=selected['metadata'].get('namespace','')
        def matches(subject):
            if subject['kind']=='User':return subject['name']==attrs['username']
            if subject['kind']=='Group':return subject['name'] in attrs['groups']
            if subject['kind']=='ServiceAccount':
                subject_ns=subject.get('namespace') or namespace
                return bool(subject_ns) and attrs['username']=='system:serviceaccount:'+subject_ns+':'+subject['name']
            return False
        if not any(matches(subject) for subject in selected.get('subjects') or []):continue
        ref=selected['roleRef'];key=(ref['kind'],namespace if ref['kind']=='Role' else '',ref['name'])
        require(key in roles, 'Frozen eligible binding has unresolved role')
        result.extend(copy.deepcopy(roles[key].get('rules') or []))
    return result


def audit_native(execution, case):
    require(type(execution.get('returncode')) is int and execution['returncode']==0, 'Native policy change failed')
    value=execution.get('data'); expected=case['expected']
    fields={'schema_version','kind','valid','validation_errors','initial','special','resolutions','coverage','actor_rules',
            'only_gc_fields','storage_calls','storage_validation','guard_accepted','accepted','error','error_reason','http_status'}
    require(isinstance(value,dict) and set(value)==fields, 'Wrong native policy-change shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_policy_change_native' and value['valid'] is True and value['validation_errors']==[], 'Invalid native policy change')
    def auth(entry, attrs, decision):
        require(isinstance(entry,dict) and set(entry)=={'attributes','decision','reason','error','granting_rule_indices'}, 'Wrong native auth shape')
        require(encoded(entry['attributes'])==encoded(attrs) and entry['decision']==decision and entry['error']=='' and isinstance(entry['reason'],str), 'Wrong native full attributes/decision')
        indices=entry['granting_rule_indices']
        require(isinstance(indices,list) and all(type(i) is int and 0<=i<len(value['actor_rules']) for i in indices)
                and indices==sorted(set(indices)) and bool(indices)==(decision=='Allow'), 'Invalid native granting rule indices')
    require(isinstance(value['actor_rules'],list) and encoded(value['actor_rules'])==encoded(eligible_rules(case)), 'Wrong native actor rule provenance')
    auth(value['initial'],initial_attributes(case),expected['initial'])
    special=expected['special']
    require(isinstance(value['special'],list) and len(value['special'])==(0 if special is None else 1), 'Wrong special check count')
    if special is not None:
        auth(value['special'][0],special_attributes(case),special)
    for field in ['accepted','guard_accepted']:
        require(type(value[field]) is bool and value[field] is expected['accepted'], 'Native accepted wrong gate')
    require(value['only_gc_fields'] is False, 'GC shortcut entered supported spec-changing operation')
    require(type(value['storage_calls']) is int and value['storage_calls']==int(expected['accepted']) and value['storage_validation']==[], 'Unexpected native terminal validation')
    wanted_status=(201 if case['contract']['operation']=='create' else 200) if expected['accepted'] else 403
    require(type(value['http_status']) is int and value['http_status']==wanted_status, 'Native HTTP gate status wrong')
    if expected['accepted'] or expected['initial']=='NoOpinion':
        require(value['error']=='' and value['error_reason']=='', 'Unexpected native storage error')
    else:
        require(isinstance(value['error'],str) and value['error'] and value['error_reason']=='Forbidden', 'Missing native escalation denial')
    if expected['covered'] is None:
        require(value['coverage']==[] and value['resolutions']==[], 'Bypassed check fabricated coverage')
    else:
        require(isinstance(value['coverage'],list) and len(value['coverage'])==1, 'Missing native coverage')
        coverage=dict(owner_rules=expected['owner_rules'],required_rules=expected['required_rules'],covered=expected['covered'],missing_rules=expected['missing_rules'])
        require(encoded(value['coverage'][0])==encoded(coverage), 'Native full policy coverage differs')
        require(encoded(value['actor_rules'])==encoded(expected['owner_rules']), 'Native actor rules differ from coverage')
        wanted=[]; attrs=initial_attributes(case); obj=target_object(case)
        if obj['kind'].endswith('Binding'):
            wanted.append(dict(kind='reference',namespace=attrs['namespace'],username='',groups=[],role_ref=obj['roleRef'],rules=expected['required_rules'],error=''))
        wanted.append(dict(kind='owner',namespace=attrs['namespace'],username=attrs['username'],groups=attrs['groups'],role_ref=None,rules=expected['owner_rules'],error=''))
        require(encoded(value['resolutions'])==encoded(wanted), 'Native RulesFor/reference operands differ')
    return value


def audit_native_boundary(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==1, 'Native boundary accepted')
    value=execution.get('data')
    require(isinstance(value,dict) and type(value.get('schema_version')) is int and value['schema_version']==1
            and value.get('kind')=='rbac_policy_change_native' and value.get('valid') is False and value.get('accepted') is False
            and value.get('guard_accepted') is False and value.get('initial') is None and value.get('special')==[]
            and value.get('resolutions')==[] and value.get('coverage')==[] and value.get('actor_rules')==[]
            and type(value.get('storage_calls')) is int and value['storage_calls']==0,
            'Native boundary reached authorization/storage')
    require(isinstance(value.get('validation_errors'),list) and value['validation_errors']
            and all(isinstance(error,str) and error for error in value['validation_errors']), 'Missing native boundary diagnostic')


def normalized_rule(value):
    require(isinstance(value,dict) and set(value)<=set(['verbs','apiGroups','resources','resourceNames','nonResourceURLs']), 'Unknown rule field')
    for key, items in value.items():
        require(isinstance(items,list) and all(isinstance(item,str) for item in items), 'Wrong rule array')
    require(value.get('verbs'), 'Missing rule verb')
    return {key:items for key,items in value.items() if items}


def indexed_missing(case):
    missing=copy.deepcopy(case['expected']['missing_rules']);result=[]
    for rule_index, selected in enumerate(case['expected']['required_rules']):
        for atom_index, atom in enumerate(atoms([selected])):
            if missing and encoded(atom)==encoded(missing[0]):
                result.append(dict(proposed_rule_index=rule_index,atom_index=atom_index,rule=atom));missing.pop(0)
    require(not missing, 'Frozen missing atom is absent from target policy')
    return result


def audit_model(execution, case, native):
    require(type(execution.get('returncode')) is int and execution['returncode']==0, 'Deterministic model command failed')
    value=execution.get('data'); expected=case['expected']
    require(isinstance(value,dict) and set(value)=={'result','authorization','reason'}, 'Wrong deterministic adapter shape')
    require(value['result']==('authorization_allowed' if expected['accepted'] else 'authorization_failed') and isinstance(value['reason'],str), 'Wrong deterministic authorization result')
    auth=value['authorization']
    require(isinstance(auth,dict) and set(auth)=={'method','allowed','reason','initial','special','coverage'}, 'Wrong model authorization shape')
    require(auth['method']=='deterministic-native-rbac-policy-coverage' and type(auth['allowed']) is bool
            and auth['allowed'] is expected['accepted'] and isinstance(auth['reason'],str), 'Wrong model method/authorization')
    def check(entry, reference):
        require(isinstance(entry,dict) and set(entry)=={'attributes','granting_rule_indices'}, 'Wrong model request evidence')
        attrs=reference['attributes']
        wanted=dict(verb=attrs['verb'],api_group=attrs['apiGroup'],namespace=attrs['namespace'],
                    resource=attrs['resource'],subresource=attrs['subresource'],name=attrs['name'])
        require(encoded(entry['attributes'])==encoded(wanted), 'Model initial/special coordinates differ')
        require(encoded(entry['granting_rule_indices'])==encoded(reference['granting_rule_indices']), 'Model granting origins differ')
    check(auth['initial'],native['initial'])
    if expected['special'] is None:
        require(auth['special'] is None, 'Model ran skipped special check')
    else:
        check(auth['special'],native['special'][0])
    if expected['covered'] is None:
        require(auth['coverage'] is None, 'Model fabricated skipped coverage')
    else:
        coverage=auth['coverage']
        require(isinstance(coverage,dict) and set(coverage)=={'covered','atom_count','missing'}, 'Wrong model coverage shape')
        require(type(coverage['covered']) is bool and coverage['covered'] is expected['covered'], 'Wrong model coverage result')
        require(type(coverage['atom_count']) is int and coverage['atom_count']==len(atoms(expected['required_rules'])), 'Wrong full policy atom count')
        wanted=indexed_missing(case)
        require(isinstance(coverage['missing'],list) and len(coverage['missing'])==len(wanted), 'Wrong missing atom count')
        for actual, target in zip(coverage['missing'],wanted):
            require(isinstance(actual,dict) and set(actual)==set(target), 'Wrong missing atom evidence shape')
            for key in ['proposed_rule_index','atom_index']:
                require(type(actual[key]) is int and actual[key]==target[key], 'Wrong missing atom index')
            require(encoded(normalized_rule(actual['rule']))==encoded(target['rule']), 'Wrong missing policy atom')
    return value


def audit_model_boundary(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==0, 'Model boundary command failed')
    value=execution.get('data')
    require(isinstance(value,dict) and set(value)=={'result','authorization','reason'} and value['result']=='unknown'
            and value['authorization'] is None and isinstance(value['reason'],str) and value['reason'], 'Unsupported model boundary yielded authorization')


def composition_cases():
    ids=['authorized-binding-violates-access','authorized-binding-loses-preservation',
         'authorized-binding-approved-scope','authorized-binding-unapproved-scope']
    inventory={case['id']:case for case in cases()}
    return [inventory[id_] for id_ in ids]


def composition_result(case):
    if case['expected']['result']=='proved':return 'valid_change'
    return 'out_of_scope_regression' if case['expected']['stage']=='preservation' else 'contract_failed'


def input_identities(case):
    return {name:dict(sha256=hashlib.sha256(encoded(case[name])).hexdigest(),bytes=len(encoded(case[name])))
            for name in ['before','after']}


def normalized_change_contract(value):
    require(isinstance(value,dict) and set(value)=={'schema_version','kind','actor','operation','target','requirements'}, 'Wrong frozen change contract shape')
    result=copy.deepcopy(value)
    result['requirements']=controller.coverage.normalized_contract(result['requirements'])
    return result


def audit_composition(execution,case,native):
    wanted=composition_result(case);value=execution.get('data')
    fields={'schema_version','kind','result','reason','assurance','frozen_spec','inputs','authorization','verification'}
    require(isinstance(value,dict) and set(value)==fields, 'Wrong composed report shape')
    require(type(execution.get('returncode')) is int and execution['returncode']==(0 if wanted=='valid_change' else 3)
            and value['result']==wanted, 'Wrong composed result/exit')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='kubernetes-rbac-policy-change', 'Wrong composed schema/kind')
    require(isinstance(value['reason'],str) and value['reason'], 'Missing composed reason')
    require(value['assurance']==dict(profile='kubernetes-rbac-v1.34-policy-change-v1',status='within_profile'), 'Wrong composed profile')
    frozen=value['frozen_spec']
    require(isinstance(frozen,dict) and set(frozen)=={'schema_version','kind','canonical'} and type(frozen['schema_version']) is int
            and frozen['schema_version']==1 and frozen['kind']=='kubernetes-rbac-policy-change' and isinstance(frozen['canonical'],str), 'Missing frozen change identity')
    require(encoded(normalized_change_contract(strict_json(frozen['canonical'])))==encoded(normalized_change_contract(case['contract'])), 'Composed frozen contract changed')
    require(encoded(value['inputs'])==encoded(input_identities(case)), 'Composed before/after bytes changed')
    # The outer adapter must retain the exact independently checked prerequisite.
    audit_model(dict(returncode=0,data=dict(result='authorization_allowed',authorization=value['authorization'],reason='')),case,native)
    verification=value['verification']
    require(isinstance(verification,dict) and set(verification)=={'comparison_report','candidate_report'}, 'Missing composed verification stages')
    spec=case['contract']['requirements']
    candidate_result='violated' if wanted=='contract_failed' else 'proved'
    candidate=controller.audit_report(dict(returncode=controller.EXIT_CODES[candidate_result],data=verification['candidate_report']),spec,candidate_result)
    comparison_result='proved' if wanted=='valid_change' else 'violated'
    comparison=controller.audit_report(dict(returncode=controller.EXIT_CODES[comparison_result],data=verification['comparison_report']),spec,
                                       comparison_result,comparison=wanted!='contract_failed')
    if wanted=='contract_failed':
        require(encoded(candidate)==encoded(comparison), 'Access failure was replaced by a preservation result')
    return value


def composition_witness(value,case):
    result=composition_result(case)
    if result=='valid_change':return None
    spec=case['contract']['requirements'];target=target_object(case)
    report=value['verification']['candidate_report' if result=='contract_failed' else 'comparison_report']
    if result=='contract_failed':
        failed=[clause for clause in spec['clauses'] if clause['kind']=='must_not_grant']
        require(len(failed)==1, 'Frozen composition requires one forbidden clause')
        row=controller.audit_witness(report,dict(contract=spec,failed=failed[0]['name']))
    else:
        ref=target['roleRef'];namespace=target['metadata'].get('namespace','') if ref['kind']=='Role' else ''
        referenced=next(obj for obj in case['before']['items'] if obj['kind']==ref['kind']
                        and obj['metadata']['name']==ref['name'] and obj['metadata'].get('namespace','')==namespace)
        require(len(referenced['rules'])==1 and len(target['subjects'])==1, 'Frozen preservation case must have one added grant')
        permission=referenced['rules'][0]
        wanted=dict(kind=permission['resources'][0],operation=permission['verbs'][0],user=target['subjects'][0]['name'])
        row=controller.audit_witness(report,dict(contract=spec,preservation=wanted),True)
        require(row['namespace']==target['metadata']['namespace'] and row['name'] in permission['resourceNames'], 'Preservation witness outside the changed binding permission')
    binding_label='RoleBinding/'+target['metadata']['namespace']+'/'+target['metadata']['name']
    role_label='ClusterRole/'+target['roleRef']['name']
    require(report['counterexample']['granting_rules']==[binding_label+' -> '+role_label+'/rules/0'], 'Witness grant origin is not the introduced binding')
    return row


def audit_composition_replay(before,after,row):
    old=controller.coverage.audit_native_urls(before,[row])['witness']
    new=controller.coverage.audit_native_urls(after,[row])['witness']
    require(old=='NoOpinion' and new=='Allow', 'Composed witness is not an introduced native grant')


def replay_composition(reference,folder,row,environment):
    path=folder/'composition-witness-urls.json'
    save(path,[controller.as_url(row)])
    before=execute([reference,'--coverage-urls',folder/'before.json',path],folder/'composition-witness-before.json',environment)
    after=execute([reference,'--coverage-urls',folder/'after.json',path],folder/'composition-witness-after.json',environment)
    audit_composition_replay(before,after,row)
    return path


def planned_inputs():
    result={'source-inventory.json':encoded(SOURCE_FILES),'linkage.json':encoded(LINKAGE)}
    for case in cases():
        for key in ['before','after','contract','expected']:
            result[case['id']+'/'+key+'.json']=encoded(case[key])
    for case in rejections():
        for key in ['before','after','contract']:
            result['rejections/'+case['id']+'/'+key+'.json']=encoded(case[key])
    return result


def rejections():
    source=next(c for c in cases() if c['id']=='role-update-existing-covered-future-policy')
    result=[]
    for name in ['no-op','metadata-only','role-rules-null-empty','target-missing','create-existing','wrong-actor','masters',
                 'other-object-metadata','other-object-array-order','multiple-added','patch','delete','missing-namespace']:
        case=copy.deepcopy(source);case['id']=name
        before=case['before']['items'];after=case['after']['items'];spec=case['contract']
        if name=='no-op':after[-1]=copy.deepcopy(before[-1])
        elif name=='metadata-only':
            after[-1]=copy.deepcopy(before[-1]);after[-1]['metadata']['annotations']={'changed':'true'}
        elif name=='role-rules-null-empty':
            before[-1]['rules']=None;after[-1]['rules']=[]
        elif name=='target-missing':before.pop()
        elif name=='create-existing':spec['operation']='create'
        elif name=='wrong-actor':spec['actor']='not-frozen'
        elif name=='masters':spec['requirements']['context']['identities'][-1]['groups'].append('system:masters')
        elif name=='other-object-metadata':after[0]['metadata']['annotations']={'changed':'true'}
        elif name=='other-object-array-order':after[2]['rules'].reverse()
        elif name=='multiple-added':after.append(role('Role','other','team-a'))
        elif name in ['patch','delete']:spec['operation']=name
        else:spec['target']['namespace']=None
        result.append(case)
    source=next(c for c in cases() if c['id']=='rolebinding-update-existing-explicit-special')
    for name in ['changed-role-ref','subjects-null-empty','subjects-omitted-empty']:
        case=copy.deepcopy(source);case['id']=name
        if name=='changed-role-ref':case['after']['items'][-1]['roleRef']['name']='actor-authority'
        else:
            case['before']['items'][-1]['subjects']=None
            if name=='subjects-omitted-empty':case['before']['items'][-1].pop('subjects')
            case['after']['items'][-1]['subjects']=[]
        result.append(case)
    source=next(c for c in cases() if c['id']=='clusterrole-update-existing-covered-future-policy')
    for state in ['before','after']:
        case=copy.deepcopy(source);case['id']='aggregate-target-'+state
        case[state]['items'][-1]['aggregationRule']={'clusterRoleSelectors':[{'matchLabels':{'absent':'yes'}}]}
        case[state]['items'][-1]['rules']=[]
        result.append(case)
    return result


def source_provenance(metadata_file):
    metadata=read_json(metadata_file); root=Path(metadata['Dir']).parent
    roots={module:root/(module+'@'+('v1.34.0' if module=='kubernetes' else 'v0.34.0')) for module in SOURCE_FILES}
    pins=read_json(HERE/'source-pins.json'); require(set(pins)==set(SOURCE_FILES), 'Wrong source modules')
    result={}
    for module, entries in pins.items():
        require(set(entries)==set(SOURCE_FILES[module]), 'Wrong pinned source inventory')
        for relative, sha in entries.items():
            path=roots[module]/relative
            require(digest(path)==sha, 'Pinned source changed '+str(path)); result[str(path)]=sha
    return result


def audit_linkage(execution):
    require(type(execution.get('returncode')) is int and execution['returncode']==0, 'Native linkage command failed')
    value=execution.get('data')
    require(isinstance(value,dict) and set(value)=={'schema_version','kind','go_version','modules','functions'}, 'Wrong policy linkage shape')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='rbac_policy_change_native_linkage', 'Wrong policy linkage schema')
    require(isinstance(value['go_version'],str) and value['go_version'].startswith('go1.'), 'Missing native Go version')
    versions={module:('v1.34.0' if module=='kubernetes' else 'v0.34.0') for module in ['kubernetes','apiserver','api','apimachinery','component-helpers']}
    require(isinstance(value['modules'],dict), 'Missing linked module inventory')
    for module, version in versions.items():
        require(value['modules'].get('k8s.io/'+module)==version, 'Wrong linked module '+module)
    require(isinstance(value['functions'],dict) and set(value['functions'])==set(LINKAGE), 'Wrong native function inventory')
    for label, (module, source, line, function) in LINKAGE.items():
        entry=value['functions'][label]
        require(isinstance(entry,dict) and set(entry)=={'file','line','function'}, 'Wrong native function shape')
        require(entry['function']=='k8s.io/'+module+'/'+function and type(entry['line']) is int and entry['line'] in [line,line+1], 'Wrong native linked function '+label)
        # Go's -trimpath retains the required v0.0.0 staging version in this
        # function's filename. BuildInfo and checked disk source independently
        # pin its actual replacement to component-helpers v0.34.0.
        path_version='v0.0.0' if module=='component-helpers' else versions[module]
        require(isinstance(entry['file'],str) and entry['file'].endswith('k8s.io/'+module+'@'+path_version+'/'+source), 'Wrong native source '+label)
    return value


def audit_completion(result,native_only=False):
    require(result.get('failures')==[] and result.get('native_only') is native_only, 'Wrong completion mode')
    require(type(result.get('native_cases')) is int and result['native_cases']==len(cases()), 'Missing native case count')
    require(encoded(result.get('cases'))==encoded({case['id']:case['expected']['accepted'] for case in cases()}), 'Missing native case inventory')
    for name,wanted in [('native_boundaries',len(rejections())),('model_cases',0 if native_only else len(cases())),
                        ('model_boundaries',0 if native_only else len(rejections())),
                        ('composition_cases',0 if native_only else len(composition_cases())),
                        ('composition_access_witness_replays',0 if native_only else 1),
                        ('composition_preservation_witness_replays',0 if native_only else 2),
                        ('composition_native_checks',0 if native_only else 6)]:
        require(type(result.get(name)) is int and result[name]==wanted, 'Missing counter '+name)
    expected={} if native_only else {case['id']:composition_result(case) for case in composition_cases()}
    require(encoded(result.get('compositions'))==encoded(expected), 'Missing composed case inventory')
    for key in ['inputs_unchanged','binaries_unchanged','native_linkage_verified']:
        require(result.get(key) is True, 'Missing provenance '+key)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ['reference','module-metadata','output']:
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--model',type=Path)
    parser.add_argument('--soundcheck',type=Path)
    parser.add_argument('--z3',default='z3')
    parser.add_argument('--native-only',action='store_true')
    args=parser.parse_args(argv)
    result=dict(schema_version=1,kind='rbac_policy_change_conformance',complete=False,native_only=args.native_only,
                native_cases=0,native_boundaries=0,model_cases=0,model_boundaries=0,cases={},
                composition_cases=0,composition_access_witness_replays=0,composition_preservation_witness_replays=0,
                composition_native_checks=0,compositions={},failures=[],input_sha256={},source_sha256={},binary_sha256={},upstream_source_sha256={},
                limitations=['Finite synthetic conformance is not a live deployment benchmark or universal model-correctness proof.',
                             'Native policybased wrappers use fixture storage and native strategy validation; no persistence, admission or concurrency guarantee.'])
    save(args.output,result)
    try:
        require(args.native_only or args.model is not None, 'Deterministic comparison requires --model')
        require(args.native_only or args.soundcheck is not None, 'Composed comparison requires --soundcheck')
        result['reference']=module_provenance(args.module_metadata)
        result['upstream_source_sha256']=source_provenance(args.module_metadata)
        inputs=planned_inputs();audit_pins(inputs,read_json(HERE/'inputs.json'))
        artifacts=args.output.parent/'artifacts'
        for name, content in inputs.items():
            path=artifacts/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);result['input_sha256'][str(path)]=digest(path)
        source_dir=Path(__file__).resolve().parent
        paths=[Path(__file__),source_dir/'test_policy_changes_runner.py',HERE/'inputs.json',HERE/'source-pins.json',HERE/'generate.py',args.module_metadata]
        paths+=sorted(source_dir.glob('run*.py'))+sorted((source_dir/'oracle').glob('*.go'))+[source_dir/'oracle/go.mod',source_dir/'oracle/go.sum',source_dir/'oracle/module-pins.json']
        result['source_sha256']={str(path):digest(path) for path in paths}
        binaries=[args.reference];solver=None
        if not args.native_only:
            solver=shutil.which(args.z3)
            require(solver is not None, 'Composed comparison requires Z3')
            solver=Path(solver).resolve()
            binaries += [args.model,args.soundcheck,solver]
        result['binary_sha256']={str(path):digest(path) for path in binaries}
        save(args.output.parent/'before-execution.json',result)
        result['native_linkage']=audit_linkage(execute([args.reference,'--policy-change-reference-info'],args.output.parent/'native-linkage.json',dict(os.environ)))
        result['native_linkage_verified']=True
        native_results={}
        for case in cases():
            folder=artifacts/case['id']
            response=execute([args.reference,'--policy-change-reference',folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ))
            native=audit_native(response,case)
            native_results[case['id']]=native
            result['cases'][case['id']]=native['accepted'];result['native_cases']+=1;save(args.output,result)
            if not args.native_only:
                audit_model(execute([args.model,folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'model.json',dict(os.environ)),case,native)
                result['model_cases']+=1
            print(case['id']+': frozen/native'+('' if args.native_only else '/model')+' agree',flush=True)
        for case in rejections():
            folder=artifacts/'rejections'/case['id']
            audit_native_boundary(execute([args.reference,'--policy-change-reference',folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'native.json',dict(os.environ)))
            result['native_boundaries']+=1
            if not args.native_only:
                audit_model_boundary(execute([args.model,folder/'before.json',folder/'after.json',folder/'contract.json'],folder/'model.json',dict(os.environ)))
                result['model_boundaries']+=1
        if not args.native_only:
            # Only these four pre-frozen cases invoke the solver-backed CLI.
            # All 92 authorization comparisons above use the deterministic
            # adapter and native wrappers, independently of the SMT reader.
            with tempfile.TemporaryDirectory(prefix='soundcheck-policy-change-z3-') as directory:
                Path(directory,'z3').symlink_to(solver)
                environment=dict(os.environ)
                environment['PATH']=directory+os.pathsep+environment.get('PATH','')
                for case in composition_cases():
                    folder=artifacts/case['id']
                    execution=execute([args.soundcheck,'rbac','change',folder/'before.json',folder/'after.json','--contract',folder/'contract.json','--format','json'],folder/'composition.json',environment)
                    composed=audit_composition(execution,case,native_results[case['id']])
                    result['compositions'][case['id']]=composed['result'];result['composition_cases']+=1
                    row=composition_witness(composed,case)
                    if row is not None:
                        path=replay_composition(args.reference,folder,row,environment)
                        result['input_sha256'][str(path)]=digest(path)
                        counter='composition_access_witness_replays' if composed['result']=='contract_failed' else 'composition_preservation_witness_replays'
                        result[counter]+=1;result['composition_native_checks']+=2
                    save(args.output,result)
                    print(case['id']+': composed CLI stages and native witness replay agree',flush=True)
        for key in ['input_sha256','source_sha256','binary_sha256','upstream_source_sha256']:
            require(all(digest(Path(path))==sha for path,sha in result[key].items()),key+' changed during execution')
        audit_pins(planned_inputs(),read_json(HERE/'inputs.json'))
        result.update(inputs_unchanged=True,binaries_unchanged=True);audit_completion(result,args.native_only);result['complete']=True
    except (RuntimeError,OSError,ValueError,KeyError,TypeError) as error:
        result['failures'].append(str(error))
    save(args.output,result)
    print({key:result[key] for key in ['complete','native_only','native_cases','native_boundaries','model_cases','model_boundaries','composition_cases','composition_access_witness_replays','composition_preservation_witness_replays','composition_native_checks','failures']})
    return 0 if result['complete'] else 1


if __name__=='__main__':
    raise SystemExit(main())
