open Hash

type algo =
  | SHA1
  | SHA256

type config =
  { secret : bytes;
    digits : int;
    period : int;
    t0 : int64;
    algo : algo
  }

let default_config (secret : bytes) : config =
    { secret; digits = 6; period = 30; t0 = 0L; algo = SHA1 }
;;

let counter_of_timestamp (cfg : config) ~(timestamp_s : int64) : int64 =
    if cfg.period <= 0 then invalid_arg "totp: period must be > 0";

    let delta = Int64.sub timestamp_s cfg.t0 in

    if Int64.compare delta 0L < 0 then
      invalid_arg "totp: timestamp is before t0";

    Int64.div delta (Int64.of_int cfg.period)
;;

let pow10 n =
    let rec loop acc i =
        if i = 0 then
          acc
        else
          loop (acc * 10) (i - 1)
    in
    loop 1 n
;;

let hmac_by_algo (cfg : config) (msg : bytes) =
    let algo =
        match cfg.algo with
        | SHA1 -> `Sha_1
        | SHA256 -> `Sha_256
    in

    Hmac.hmac_bytes msg ~key:cfg.secret ~algo
;;
let htop_int (cfg : config) ~(counter : int64) : int =
    if cfg.digits <= 0 then invalid_arg "totp: digits must be > 0";

    let counter_bytes = Bytes.create 8 in
    Bytes.set_int64_be counter_bytes 0 counter;

    let mac = hmac_by_algo cfg counter_bytes in
    let mac_len = Bytes.length mac in

    if mac_len < 20 then invalid_arg "totp: invalid HMAC length";

    let offset = Char.code (Bytes.get mac (mac_len - 1)) land 0x0f in
    if offset + 3 >= mac_len then invalid_arg "totp: invalid dynamic offset";

    let b0 = Char.code (Bytes.get mac offset) land 0x7f in
    let b1 = Char.code (Bytes.get mac (offset + 1)) in
    let b2 = Char.code (Bytes.get mac (offset + 2)) in
    let b3 = Char.code (Bytes.get mac (offset + 3)) in

    let code31 = (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3 in

    code31 mod pow10 cfg.digits
;;

let htop_code (cfg : config) ~(counter : int64) : string =
    Printf.sprintf "%0*d" cfg.digits (htop_int cfg ~counter)
;;

let totp_at (cfg : config) ~(timestamp_s : int64) : string =
    failwith "not implement"
;;

let totp_now (cfg : config) ~(timestamp_s : int64) : string =
    failwith "not implement"
;;

let verify_at
      ?(window = 20)
      (cfg : string)
      ~(timestamp_s : int64)
      ~(code : string)
  : bool
  =
    failwith "not implement"
;;

let verify_now
      ?(window = 20)
      (cfg : string)
      ~(now_s : unit -> int64)
      ~(code : string)
  : bool
  =
    failwith "not implement"
;;

let equal_code_ct (a : string) (b : string) : bool = failwith "not implement"
