module K=Soundcheck_kubernetes_rbac
open Soundcheck_core
let checks=ref 0
let check label value=incr checks;if not value then failwith label
let request ?(method_="get") path : Ir.request =
  {principal=Authenticated "alice";action=method_;resource=path;object_request=None;
   context=[];source=0l;host="";scheme="";sni=""}
let () =
  let cases=["/",true;"/version",true;"/healthz/",true;"/healthz/ping",true;
    "/metrics",true;"/metrics/component",true;"/api",true;"/api/",true;
    "/api/v1",true;"/api/v1/",true;"/api/v1/pods",false;
    "/apis",true;"/apis/apps",true;"/apis/apps/v1",true;"/apis/apps/v1/",true;
    "/apis/apps/v1/deployments",false;"/apis/apps/v1/deployments/a",false;
    "/api/v1/namespaces/team-a",false;"/api/v1/watch",false;
    "/other/v1/pods",true;"/API/v1/pods",true;"/a.b/_a~B-9/",true;
    "",false;"healthz",false;"//",false;"/healthz//",false;
    "/.",false;"/..",false;"/./healthz",false;"/healthz/../x",false;
    "/healthz/./",false;"/healthz/%2e",false;"/healthz?x=1",false;
    "/healthz#x",false;"/\xc3\xa9",false;"/healthz\n",false;
    "/..hidden",true;"/...",true;"/a.b/",true] in
  List.iter (fun (path,expected) ->
    check ("path predicate "^path) (K.Url_domain.valid_path path=expected);
    List.iter (fun method_ ->
      check ("request predicate "^path) (Ir.matches K.Url_domain.condition (request ~method_ path)=expected)) K.Url_domain.methods) cases;
  List.iter (fun method_ ->check "unsupported HTTP method" (not (Ir.matches K.Url_domain.condition (request ~method_ "/version")))) ["GET";"watch";"list";"apply-missing";"trace";""];
  check "object request disjoint" (not (Ir.matches K.Url_domain.condition
    {(request "/version") with object_request=Some {namespace="";resource_kind="nodes";name="n"}}));
  List.iter (fun (rule,path,expected) ->check "native trailing-star rule" (Ir.matches (K.Url_domain.rule_condition rule) (request path)=expected))
    ["*","/version",true;"**","/version",true;"/healthz*","/healthz",true;
     "/healthz**","/healthz/ping",true;"/healthz/*","/healthz",false;
     "/healthz/*","/healthz/",true;"/healthz","/healthz/ping",false;
     "/health*z*","/healthz",false;"","/",false];
  let parse source=K.Input.protect (fun ()->K.Url_domain.parse "paths" (K.Input.parse source)) in
  List.iter (fun value ->check "invalid selector" (Result.is_error (parse value)))
    ["null";"{}";{|{"exact":"/api/v1/pods"}|};{|{"exact":"/healthz?x=1"}|};
     {|{"prefix":"/" ,"exact":"/version"}|};{|{"prefix":"/../"}|};{|{"prefix":""}|}];
  check "resource-only prefix is legal but empty" (Result.is_ok (parse {|{"prefix":"/api/v1/pods"}|}));
  Printf.printf "RBAC URL domain: %d checks passed\n" !checks
