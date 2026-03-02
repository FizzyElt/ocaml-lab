type algo =
  | SHA1
  | SHA256
  | SHA512

type config =
  { secret : bytes;
    digits : int;
    period : int;
    t0 : int64;
    algo : algo
  }

val default_config : bytes -> config

val hotp_int : config -> counter:int64 -> int

val hotp_code : config -> counter:int64 -> string

val totp_at : config -> timestamp_s:int64 -> string

val totp_now : config -> timestamp_s:int64 -> string

val verify_at
  :  ?window:int ->
  config ->
  timestamp_s:int64 ->
  code:string ->
  bool

val verify_now
  :  ?window:int ->
  config ->
  now_s:(unit -> int64) ->
  code:string ->
  bool
