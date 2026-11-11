open Input

type identity = { username : string; groups : string list }

let parse_context value =
  let p = "context" in
  let o = obj p [ "schema_version"; "snapshot_complete"; "identities" ] value in
  (match field p "schema_version" o with
   | `Number "1" -> ()
   | _ -> reject p "schema_version must be 1");
  (match field p "snapshot_complete" o with
   | `Bool true -> ()
   | _ -> reject (p ^ ".snapshot_complete") "must be true only for an independently established complete inventory; setting this assertion does not establish completeness");
  let seen = Hashtbl.create 8 in
  let identities = arr "context.identities" (field p "identities" o) in
  if identities = [] then reject p "identities must be nonempty";
  identities
  |> List.mapi (fun i value ->
         let p = Printf.sprintf "context.identities[%d]" i in
         let o = obj p [ "username"; "groups" ] value in
         let username = string_field p "username" o |> nonempty (p ^ ".username") in
         let groups = strings (p ^ ".groups") (field p "groups" o) in
         List.iter (fun g -> ignore (nonempty (p ^ ".groups") g)) groups;
         if List.length groups <> List.length (List.sort_uniq String.compare groups)
         then reject (p ^ ".groups") "duplicate group; supply each exact trusted group once";
         if Hashtbl.mem seen username then reject (p ^ ".username") (Printf.sprintf "duplicate username %S" username);
         Hashtbl.add seen username ();
         { username; groups = List.sort String.compare groups })
