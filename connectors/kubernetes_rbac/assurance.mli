val profile_id : string
val read_profile_id : string
val id_for_version : int -> string
val assumptions : string list
val read_assumptions : string list
val assessment : ?version:int -> ?reason:string -> unit -> Soundcheck_core.Report.assurance
val profile_json : ?version:int -> unit -> string
val profile_human : ?version:int -> unit -> string
