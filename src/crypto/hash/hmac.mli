val hmac_bytes : bytes -> key:bytes -> algo:[ `Sha_1 | `Sha_256 ] -> bytes

val hmac_verify_bytes
  :  bytes ->
  key:bytes ->
  msg:bytes ->
  algo:[ `Sha_1 | `Sha_256 ] ->
  bool

val hmac : string -> key:string -> algo:[ `Sha_1 | `Sha_256 ] -> string

val hmac_verify
  :  string ->
  key:string ->
  msg:string ->
  algo:[ `Sha_1 | `Sha_256 ] ->
  bool
