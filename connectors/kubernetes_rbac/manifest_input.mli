(** Bounded, full-stream input reader for explicit preparation only. Raises
    [Input.Unsupported] on malformed, ambiguous or unsupported input. *)
type format = Json | Yaml
val format_name : format -> string
val parse : format -> string -> Strict_json.value option list
(** [None] denotes a genuinely empty YAML document, not an explicit null. *)
