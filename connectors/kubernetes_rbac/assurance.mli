val profile_id : string
val assumptions : string list
val assessment : ?reason:string -> unit -> Soundcheck_core.Report.assurance
val profile_json : unit -> string
val profile_human : unit -> string
