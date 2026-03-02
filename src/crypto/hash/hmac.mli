type algo =
  [ `Sha_512
  | `Sha_256
  | `Sha_1
  ]

val hmac_bytes : bytes -> key:bytes -> algo:algo -> bytes

val hmac_verify_bytes : bytes -> key:bytes -> msg:bytes -> algo:algo -> bool

val hmac : string -> key:string -> algo:algo -> string

val hmac_verify : string -> key:string -> msg:string -> algo:algo -> bool
