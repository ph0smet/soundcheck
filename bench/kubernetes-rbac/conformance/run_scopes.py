#!/usr/bin/env python3
"""V4 scope contracts: synthetic acceptance cases and upstream witness replay."""
import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from run import (EXIT_CODES, decisions, digest, execute, module_provenance,
                 require, save, smt_decisions, strict_json)
from run_write_access import validate_request, witness_request

PROFILE = 'kubernetes-rbac-v1.34-scoped-read-write-v2'
VERBS = ['get', 'list', 'watch', 'update', 'patch', 'delete']
READS = ['list', 'watch']
API = 'rbac.authorization.k8s.io'


def scope(verb='get', namespace='team-a', resource='secrets', names=None, subject='app'):
    return dict(subject=subject, verb=verb, namespace=namespace, resource=resource, names=names)


def clause(name, kind, **kwargs):
    return dict(name=name, kind=kind, **scope(**kwargs))


def contract(clauses, changes=()):
    return {'schema_version': 4, 'kind': 'kubernetes-rbac-access',
            'context': {'schema_version': 1, 'snapshot_complete': True,
                        'identities': [{'username': name, 'groups': []} for name in ['app', 'ops']]},
            'clauses': clauses, 'change_scope': list(changes)}


def grant(tag, resource, verbs, namespace=None, names=None, subject='app'):
    role, binding = ('ClusterRole', 'ClusterRoleBinding') if namespace is None else ('Role', 'RoleBinding')
    metadata = dict(name=tag, **({} if namespace is None else {'namespace': namespace}))
    rule = dict(apiGroups=[''], resources=[resource], verbs=verbs)
    if names is not None:
        rule['resourceNames'] = names
    return [dict(apiVersion=API+'/v1', kind=role, metadata=metadata, rules=[rule]),
            dict(apiVersion=API+'/v1', kind=binding, metadata=metadata,
                 roleRef=dict(apiGroup=API, kind=role, name=tag),
                 subjects=[dict(kind='User', apiGroup=API, name=subject)])]


def snapshot(items):
    return dict(apiVersion='v1', kind='List', items=items)


def cases():
    """Expectations are declared before any analyzer executes; no public inputs."""
    result = []

    def add(name, spec, items, expected, baseline=None, comparison=None, witness=None):
        result.append(dict(id=name, contract=spec, snapshot=snapshot(items), expected=expected,
                           baseline=None if baseline is None else snapshot(baseline),
                           comparison=comparison, witness=witness))

    config = sum([grant('config-'+ns, 'configmaps', ['get'], ns, ['settings'])
                  for ns in ['team-a', 'team-b']], [])
    operator = grant('operator', 'configmaps', ['get', 'patch'], 'team-a', subject='ops')
    common = config + operator
    outside = {'exclude': ['team-a', 'team-b']}
    safety = [clause('outside-'+verb, 'must_not_grant', verb=verb, namespace=outside) for verb in VERBS]
    endpoints = [clause('endpoint-'+verb, 'must_not_grant', verb=verb, namespace=None) for verb in READS]
    changes = [scope(verb=verb, namespace=outside) for verb in VERBS]
    endpoint_changes = [scope(verb=verb, namespace=None) for verb in READS]
    required = clause('required', 'must_allow', namespace={'include': ['team-b', 'team-a']},
                      resource='configmaps', names=['settings'])
    spec = contract([required]+safety+endpoints, changes+endpoint_changes)
    global_grants = grant('secrets-global', 'secrets', VERBS)
    baseline = common + global_grants
    # Keep the unbound original ClusterRole. The desired snapshot omits its binding.
    repaired = common + global_grants[:1] + sum([grant('secrets-'+ns, 'secrets', VERBS, ns)
                                               for ns in ['team-a', 'team-b']], [])
    add('namespace-outside-unsafe', spec, baseline, 'violated', witness='outside-get')
    add('namespace-repair', spec, repaired, 'proved', baseline, 'proved')
    add('namespace-global-endpoint-unapproved', contract([required]+safety+endpoints, changes),
        repaired, 'proved', baseline, 'violated', witness='endpoint-preservation')
    add('namespace-lost-allowed-access', spec, common+global_grants[:1], 'proved', baseline, 'violated')
    add('namespace-secondary-regression', spec, [o for o in repaired if not
        (o['kind']=='RoleBinding' and o['metadata']['name']=='operator')], 'proved', baseline, 'violated')
    add('namespace-novel-leak', spec, repaired+grant('novel', 'secrets', ['get'], 'unseen-tenant'),
        'violated', witness='outside-get')

    cartesian = contract([clause('required', 'must_allow', namespace={'include':['team-a','team-b']},
                                 resource='configmaps', names=['x','y']),
                          clause('forbidden', 'must_not_grant')])
    diagonal = grant('a-x','configmaps',['get'],'team-a',['x']) + grant('b-y','configmaps',['get'],'team-b',['y'])
    add('namespace-name-cartesian-missing', cartesian, diagonal, 'violated', witness='required')
    complete = grant('a-xy','configmaps',['get'],'team-a',['x','y']) + grant('b-xy','configmaps',['get'],'team-b',['x','y'])
    add('namespace-name-cartesian-complete', cartesian, complete, 'proved')

    complements = [scope(verb=verb, names={'exclude':['settings'], 'include_empty':verb in READS}) for verb in VERBS]
    named_spec = contract([clause('required', 'must_allow', names=['settings'])] +
                          [dict(name='other-'+s['verb'], kind='must_not_grant', **s) for s in complements], complements)
    wide = grant('named', 'secrets', VERBS, 'team-a')
    narrow = grant('named', 'secrets', VERBS, 'team-a', ['settings'])
    add('name-complement-unsafe', named_spec, wide, 'violated', witness='other-get')
    add('name-complement-repair', named_spec, narrow, 'proved', wide, 'proved')

    positive = clause('required', 'must_allow', resource='configmaps', names=['settings'])
    empty_grant = config + grant('empty-secret', 'secrets', ['list'], 'team-a', [''])
    for include_empty, expected in [(False, 'proved'), (True, 'violated')]:
        selected = {'exclude':['settings'], 'include_empty':include_empty}
        add('name-empty-'+str(include_empty).lower(), contract([positive, clause('forbidden','must_not_grant',verb='list',names=selected)]),
            empty_grant, expected, witness='forbidden' if include_empty else None)
    empty_spec = contract([positive, clause('forbidden','must_not_grant',verb='list',names={'empty':True})])
    add('name-empty-only-leak', empty_spec, empty_grant, 'violated', witness='forbidden')
    add('name-empty-only-restricted', empty_spec, config+narrow, 'proved')
    empty_required = contract([clause('required','must_allow',verb='list',resource='configmaps',names={'empty':True}),
                               clause('forbidden','must_not_grant')])
    add('name-empty-required-missing', empty_required, grant('config','configmaps',['list'],'team-a',['settings']), 'violated', witness='required')
    add('name-empty-required-present', empty_required, grant('config','configmaps',['list'],'team-a'), 'proved')
    inconsistent = contract([clause('required','must_allow',namespace={'include':['team-a','team-b']},resource='configmaps',names=['x']),
                             clause('forbidden','must_not_grant',namespace={'exclude':['team-a']},resource='configmaps')])
    add('selector-overlap-inconsistent', inconsistent, complete, 'inconsistent')
    return result


def scope_matches(scope_, request):
    namespace, names = scope_['namespace'], scope_['names']
    if isinstance(namespace, dict):
        selected_namespace = bool(request['namespace']) and (
            request['namespace'] in namespace['include'] if 'include' in namespace else
            request['namespace'] not in namespace['exclude'])
    else:
        selected_namespace = request['namespace'] == (namespace or '')
    if names is None:
        selected_name = True
    elif isinstance(names, list):
        selected_name = request['name'] in names
    elif names.get('empty') is True:
        selected_name = request['name'] == ''
    else:
        selected_name = request['name'] not in names['exclude'] and (bool(request['name']) or names['include_empty'])
    return (scope_['subject']==request['username'] and scope_['verb']==request['verb'] and
            scope_['resource']==request['resource'] and selected_namespace and selected_name)


def normalized(contract_):
    value = copy.deepcopy(contract_)
    for identity in value['context']['identities']:
        identity['groups'].sort()
    value['context']['identities'].sort(key=lambda i:i['username'])
    for selected in value['clauses']+value['change_scope']:
        for field in ['namespace','names']:
            selector = selected[field]
            if isinstance(selector, list):
                selector.sort()
            elif isinstance(selector, dict):
                for entry in selector.values():
                    if isinstance(entry, list):
                        entry.sort()
    changes = {json.dumps(s,sort_keys=True):s for s in value['change_scope']}
    value['change_scope'] = [changes[key] for key in sorted(changes)]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference','model','soundcheck','module-metadata','output']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--z3', default='z3')
    args = parser.parse_args()
    for name,value in vars(args).items():
        if isinstance(value,Path):
            setattr(args,name,value.resolve())
    z3 = shutil.which(args.z3)
    require(z3 is not None, 'Z3 is required')
    environment = dict(os.environ)
    # The CLI invokes z3 by name, even if the override has another basename.
    solver_directory = tempfile.TemporaryDirectory(prefix='soundcheck-scopes-z3-')
    Path(solver_directory.name,'z3').symlink_to(Path(z3).resolve())
    environment['PATH'] = solver_directory.name+os.pathsep+environment.get('PATH','')
    report = dict(complete=False, profile=PROFILE, reference=module_provenance(args.module_metadata),
                  matrix_comparisons=0, contract_witness_replays=0, preservation_witness_replays=0,
                  cases={}, failures=[], input_sha256={},
                  binary_sha256={str(path):digest(path) for path in [args.reference,args.model,args.soundcheck,Path(z3)]},
                  limits=['Synthetic scope acceptance cases, not public deployment benchmarks.',
                          'Finite oracle checks and concrete witness replay are not a universal proof of the encoder.'])
    artifacts = args.output.parent/'artifacts'
    try:
        planned = cases()
        for case in planned:
            folder = artifacts/case['id']
            for key in ['contract','snapshot','baseline']:
                if case[key] is not None:
                    path = folder/(key+'.json')
                    save(path,case[key]); report['input_sha256'][str(path)]=digest(path)
        save(args.output,report)
        for case in planned:
            name,contract_ = case['id'],case['contract']
            folder = artifacts/name
            snapshot_path,contract_path = folder/'snapshot.json',folder/'contract.json'
            identities = {i['username']:i['groups'] for i in contract_['context']['identities']}
            requests = []
            for user,groups in identities.items():
                for verb in VERBS:
                    for ns in ['team-a','team-b','unseen-tenant']+([''] if verb in READS else []):
                        for resource in ['configmaps','secrets']:
                            for obj in ['settings','x','y','unseen-name']+([''] if verb in READS else []):
                                requests.append(dict(id=str(len(requests)),username=user,groups=groups,verb=verb,apiGroup='',
                                                     resource=resource,namespace=ns,name=obj,resourceRequest=True,subresource=''))
            for request in requests:
                validate_request(request,identities)
            request_path = folder/'requests.json'; save(request_path,requests)
            upstream = decisions(execute([args.reference,snapshot_path,request_path],folder/'reference.json',environment), requests,'reference')
            model = execute([args.model,snapshot_path,contract_path,request_path],folder/'model.json',environment)
            require(upstream == decisions(model,requests,'model') == smt_decisions(model,requests,folder,'matrix',z3,environment), 'Target/model/SMT mismatch: '+name)
            report['matrix_comparisons'] += len(requests)

            def replay(path, request, label):
                request_path = folder/(label+'-request.json'); save(request_path,[request])
                return decisions(execute([args.reference,path,request_path],folder/(label+'-reference.json'),environment),[request],'reference')[request['id']]

            def check_report(execution, expected, comparison=False):
                value = execution['data']
                require(execution['returncode']==EXIT_CODES[expected] and value['result']==expected, 'Wrong verdict: '+name)
                require(type(value.get('schema_version')) is int and value['schema_version']==10 and
                        value['assurance']['profile']==PROFILE and value['assurance']['status']=='within_profile', 'Wrong assurance/report')
                frozen = value['frozen_spec']
                # Compare normalized JSON encodings, not Python numeric equality:
                # True must not equal 1, and 4.0 must not become schema integer 4.
                require(type(frozen.get('schema_version')) is int and frozen['schema_version']==4 and
                        frozen['kind']==contract_['kind'] and
                        json.dumps(normalized(strict_json(frozen['canonical'])),sort_keys=True)==
                        json.dumps(normalized(contract_),sort_keys=True), 'Frozen contract differs')
                if expected!='violated':
                    require(value.get('counterexample') is None,'Unexpected witness')
                    return value
                witness = witness_request(value,identities)
                if comparison and case['expected']=='proved':
                    require(value['property']=='rbac-repair-preservation' and value['clause']['kind']=='must_preserve', 'Wrong preservation stage')
                    require(not any(scope_matches(s,witness) for s in contract_['change_scope']), 'Witness inside approved changes')
                    require(replay(folder/'baseline.json',witness,'before')!=replay(snapshot_path,witness,'after'),'Preservation witness did not replay')
                    if case['witness']=='endpoint-preservation':
                        require(witness['namespace']=='' and witness['verb'] in READS,'Namespace complement included global endpoint')
                    report['preservation_witness_replays']+=1
                else:
                    selected = [c for c in contract_['clauses'] if c['name']==value['clause']['name']]
                    require(len(selected)==1 and selected[0]['name']==case['witness'] and selected[0]['kind']==value['clause']['kind'] and scope_matches(selected[0],witness),'Wrong clause/scope witness')
                    require(replay(snapshot_path,witness,'clause')==('Allow' if selected[0]['kind']=='must_not_grant' else 'NoOpinion'),'Contract witness did not replay')
                    report['contract_witness_replays']+=1
                return value

            verified = check_report(execute([args.soundcheck,'rbac','verify',snapshot_path,'--contract',contract_path,'--format','json'],folder/'verify.json',environment),case['expected'])
            # Finite points check requirements independently of the model's scope encoder.
            if case['expected'] in ['proved','violated']:
                violated = [c['name'] for c in contract_['clauses'] for r in requests if scope_matches(c,r)
                            and upstream[r['id']]!=('Allow' if c['kind']=='must_allow' else 'NoOpinion')]
                require(bool(violated)==(case['expected']=='violated'),'Finite obligation disagreement: '+name)
            entry = report['cases'][name] = {'contract':verified['result']}
            if case['baseline'] is not None:
                compared = check_report(execute([args.soundcheck,'rbac','compare',folder/'baseline.json',snapshot_path,'--contract',contract_path,'--format','json'],folder/'compare.json',environment),case['comparison'],True)
                entry['comparison']=compared['result']
            save(args.output,report)
            print(name+': '+str(entry),flush=True)
        require(all(digest(Path(path))==value for path,value in report['input_sha256'].items()),'Input mutated during conformance')
        report['complete']=True
    except Exception as error:
        report['failures'].append(str(error))
    finally:
        solver_directory.cleanup()
    save(args.output,report)
    if not report['complete']:
        raise RuntimeError('; '.join(report['failures']))
    print('Scope conformance: '+str(report['matrix_comparisons'])+' target/model/SMT comparisons')


if __name__=='__main__':
    main()
