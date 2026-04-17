type config =
  { hotp : Hotp.config;
    period : int;
    t0 : int64
  }

val default_config : bytes -> config

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
