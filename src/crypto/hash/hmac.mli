val hmac_bytes : bytes -> key:bytes -> bytes

val hmac_verify_bytes : bytes -> key:bytes -> msg:bytes -> bool

val hmac : string -> key:string -> string

val hmac_verify : string -> key:string -> msg:string -> bool
