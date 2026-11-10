open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings values = `A (List.map (fun value -> `String value) values)
let include_ns values = `O ["include",strings values]
let exclude_ns values = `O ["exclude",strings values]
let exclude_names ?(empty=false) values = `O ["exclude",strings values;"include_empty",`Bool empty]
let empty_name = `O ["empty",`Bool true]
let scope ?(subject="app") ?(verb="get") ?(ns=`String "team-a") ?(names=`Null) ?(resource="configmaps") () =
  ["subject",`String subject;"verb",`String verb;"namespace",ns;"resource",`String resource;"names",names]
let contract ?(version=4) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ()) ?(changes=[]) () =
  let fields values = if version=1 then List.remove_assoc "verb" values else values in
  `O ["schema_version",`Number (string_of_int version);"kind",`String K.Contract_spec.kind;
      "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
        "identities",`A [`O ["username",`String "app";"groups",strings []]]];
      "clauses",`A [
        `O (["name",`String "required";"kind",`String "must_allow"] @ fields allow);
        `O (["name",`String "forbidden";"kind",`String "must_not_grant"] @ fields deny)];
      "change_scope",`A (List.map (fun values -> `O (fields values)) changes)]
let parse value = K.Contract_spec.of_string (I.json value)
let spec value = ok (parse value)
let request verb namespace name : Ir.request =
  {principal=Authenticated "app";action=verb;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace;resource_kind="configmaps";name}}
let matches ?(verb="get") ~ns ~names namespace name =
  let selected = scope ~verb ~ns ~names () in
  let s = spec (contract ~allow:selected ~changes:[selected] ()) in
  let clause = (List.hd (K.Contract_spec.clauses s)).scope in
  let r = request verb namespace name in
  let clause_matches = Ir.matches (Ir.And [K.Lower.domain s;K.Contract_spec.scope_condition clause]) r in
  check "identical clause/change selector semantics"
    (clause_matches=Ir.matches (Ir.And [K.Lower.domain s;K.Contract_spec.approved_changes s]) r);
  clause_matches

let legacy_mixed version =
  let verbs=if version=1 then ["get"] else ["get";"list";"watch"] @
    if version=3 then ["update";"patch";"delete"] else [] in
  let changes=List.concat_map (fun subject -> List.concat_map (fun verb ->
    let namespaces=[`String "team-b";`String "team-a"] @ if List.mem verb ["list";"watch"] then [`Null] else [] in
    List.concat_map (fun ns -> List.map (fun names -> scope ~subject ~verb ~ns ~names ())
      [strings ["z";"a"];strings ["settings"];`Null]) namespaces) (List.rev verbs)) ["z-user";"app"] in
  let context=`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
    "identities",`A [`O ["username",`String "z-user";"groups",strings ["z";"a"]];
                     `O ["username",`String "app";"groups",strings []]]] in
  match contract ~version ~changes:(changes @ List.filteri (fun index _ -> index<3) changes) () with
  | `O fields -> `O (List.map (fun (key,value) -> key,if key="context" then context else value) fields)
  | _ -> assert false

let () =
  (* Captured from the pre-v4 CLI at 01ac984. Mixed empty/literal namespaces,
     name lists/null, multiple identities and duplicate changes freeze exactly. *)
  List.iter (fun (version,count,expected) ->
    let old=spec (legacy_mixed version) in
    check "legacy frozen bytes are unchanged"
      (Sha256.string (K.Contract_spec.canonical old)=expected && List.length (K.Contract_spec.changes old)=count))
    [1,12,"c8f045db5af6254dacfb93252b6f7eb48aa7cf9d0c523fbc6123f8939d243f7e";
     2,48,"fb17d81ff9c943e030be1a627c1f26389c18d6a3216b369bc9e1beb814444867";
     3,84,"400857c9d071a28be9d220e6a9948da56d7b33ae3384e5d37a0852b067d3e9f0"];
  let v4 = spec (contract ()) and v3 = spec (contract ~version:3 ()) in
  check "v4 frozen and profile identity"
    ((K.Contract_spec.frozen_spec v4).schema_version=4 && K.Assurance.id_for_version 4=K.Assurance.scoped_profile_id);
  List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
    let r = request verb ns name in
    check "selectors do not expand the authorization domain"
      (Ir.matches (K.Lower.domain v4) r=Ir.matches (K.Lower.domain v3) r))
    ["";"settings";"other";"a.b";"*";"Bad";String.make 254 'a'])
    ["";"team-a";"unseen";"Bad";"a.b";String.make 64 'a'])
    ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"];
  List.iter (fun (ns,yes) ->
    check "namespace inclusion set" (matches ~ns:(include_ns ["team-b";"team-a"]) ~names:`Null ns "settings"=yes))
    ["team-a",true;"team-b",true;"unseen",false;"",false];
  List.iter (fun verb -> List.iter (fun (ns,yes) ->
    check "namespace complement is independent of inventory and excludes endpoint"
      (matches ~verb ~ns:(exclude_ns ["team-a";"team-b"]) ~names:`Null ns "settings"=yes))
    ["team-a",false;"team-b",false;"unseen",true;"new-tenant",true;"",false;"Bad",false])
    ["get";"list";"watch";"update";"patch";"delete"];
  check "empty namespace exclusion selects every named namespace"
    (matches ~ns:(exclude_ns []) ~names:`Null "arbitrary" "settings");
  check "empty namespace exclusion never includes global collection"
    (not (matches ~verb:"list" ~ns:(exclude_ns []) ~names:`Null "" ""));
  check "explicit endpoint remains selectable"
    (matches ~verb:"watch" ~ns:`Null ~names:empty_name "" "");
  List.iter (fun verb -> List.iter (fun (name,yes) ->
    check "empty effective name is exact"
      (matches ~verb ~ns:(`String "team-a") ~names:empty_name "team-a" name=yes))
    ["",true;"settings",false;"unseen",false]) ["list";"watch"];
  List.iter (fun verb -> List.iter (fun empty -> List.iter (fun name ->
    let expected = name<>"settings" && (name<>"" || empty) in
    check "name exclusion and explicit empty membership"
      (matches ~verb ~ns:(`String "team-a") ~names:(exclude_names ~empty ["settings"]) "team-a" name=expected))
    ["";"settings";"unseen"]) [false;true]) ["list";"watch"];
  List.iter (fun verb -> List.iter (fun name ->
    check "named complements never authorize empty names"
      (matches ~verb ~ns:(`String "team-a") ~names:(exclude_names ["settings"]) "team-a" name=(name="unseen")))
    ["";"settings";"unseen"]) ["get";"update";"patch";"delete"];
  let selectors = [scope ~ns:(include_ns ["team-a"]) ();scope ~ns:(exclude_ns []) ();
                   scope ~verb:"list" ~names:empty_name ();scope ~names:(exclude_names []) ()] in
  List.iter (fun version -> List.iter (fun selected ->
    check "older clauses reject every new selector" (Result.is_error (parse (contract ~version ~allow:selected ())));
    check "older change scopes reject every new selector" (Result.is_error (parse (contract ~version ~changes:[selected] ())))) selectors) [1;2;3];
  let bad_namespaces = [include_ns [];include_ns ["team-a";"team-a"];exclude_ns ["team-a";"team-a"];
    exclude_ns [""];include_ns ["Bad"];include_ns [String.make 64 'a'];
    `O ["include",strings ["team-a"];"exclude",strings ["team-b"]];
    `O ["include",strings ["team-a"];"extra",`Bool true];`O [];`O ["exclude",`Null]] in
  List.iter (fun ns ->
    check "malformed namespace selector rejected" (Result.is_error (parse (contract ~allow:(scope ~ns ()) ())));
    check "malformed namespace changes rejected" (Result.is_error (parse (contract ~changes:[scope ~ns ()] ())))) bad_namespaces;
  let bad_names = [exclude_names [""];exclude_names ["*"];exclude_names ["settings";"settings"];
    exclude_names [String.make 254 'a'];`O ["exclude",strings ["settings"]];
    `O ["exclude",strings [];"include_empty",`String "false"];
    `O ["empty",`Bool false];`O ["empty",`Bool true;"exclude",strings []];
    `O ["exclude",strings [];"include_empty",`Bool true;"extra",`Null];`O []] in
  List.iter (fun names ->
    check "malformed names selector rejected" (Result.is_error (parse (contract ~allow:(scope ~verb:"list" ~names ()) ())));
    check "malformed names changes rejected" (Result.is_error (parse (contract ~changes:[scope ~verb:"list" ~names ()] ())))) bad_names;
  List.iter (fun verb -> List.iter (fun names ->
    check "named operation rejects empty membership" (Result.is_error (parse (contract ~allow:(scope ~verb ~names ()) ()))))
    [empty_name;exclude_names ~empty:true []]) ["get";"update";"patch";"delete"];
  let normalized = spec (contract ~allow:(scope ~ns:(include_ns ["team-b";"team-a"]) ~names:(exclude_names ["z";"a"]) ())
    ~changes:[scope ~ns:(exclude_ns ["team-b";"team-a"]) ();scope ~ns:(exclude_ns ["team-a";"team-b"]) ()] ()) in
  let canonical = K.Contract_spec.canonical normalized in
  check "selector ordering canonical and repeated changes deduplicated"
    (List.length (K.Contract_spec.changes normalized)=1 &&
     canonical=K.Contract_spec.canonical (ok (K.Contract_spec.of_string canonical)));
  let same = spec (contract ~allow:(scope ~ns:(include_ns ["team-a";"team-b"]) ~names:(exclude_names ["a";"z"]) ())
    ~changes:[scope ~ns:(exclude_ns ["team-a";"team-b"]) ()] ()) in
  check "set permutations freeze identically" (canonical=K.Contract_spec.canonical same);
  let empty_distinction value = spec (contract ~allow:(scope ~verb:"list" ~names:(exclude_names ~empty:value []) ()) ()) |> K.Contract_spec.canonical in
  check "empty-name decision is bound into frozen identity" (empty_distinction true<>empty_distinction false);
  Printf.printf "RBAC scope selectors: %d checks passed\n" !checks
