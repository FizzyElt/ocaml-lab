type algo =
  | SHA_1
  | SHA_256
  | SHA_512

type config =
  { secret : bytes;
    digits : int;
    algo : algo
  }

val default_config : bytes -> config

val hotp_int : config -> counter:int64 -> int

val hotp_code : config -> counter:int64 -> string

val verify_hotp : config -> counter:int64 -> code:string -> bool
