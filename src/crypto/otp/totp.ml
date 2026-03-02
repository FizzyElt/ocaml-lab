open Hash

type algo =
  | SHA_1
  | SHA_256
  | SHA_512

type config =
  { secret : bytes;
    digits : int;
    period : int;
    t0 : int64;
    algo : algo
  }

let default_config (secret : bytes) : config =
    { secret; digits = 6; period = 30; t0 = 0L; algo = SHA_1 }
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
        | SHA_1 -> `Sha_1
        | SHA_256 -> `Sha_256
        | SHA_512 -> `Sha_512
    in

    Hmac.hmac_bytes msg ~key:cfg.secret ~algo
;;
let hotp_int (cfg : config) ~(counter : int64) : int =
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

let hotp_code (cfg : config) ~(counter : int64) : string =
    Printf.sprintf "%0*d" cfg.digits (hotp_int cfg ~counter)
;;

let totp_at (cfg : config) ~(timestamp_s : int64) : string =
    let counter = counter_of_timestamp cfg ~timestamp_s in
    hotp_code cfg ~counter
;;

let totp_now (cfg : config) ~(timestamp_s : int64) : string =
    totp_at cfg ~timestamp_s
;;

let equal_code_ct (a : string) (b : string) : bool =
    let len_a = String.length a in
    let len_b = String.length b in
    let max_len = Int.max len_a len_b in
    let diff = ref (len_a lxor len_b) in

    for i = 0 to max_len - 1 do
      let ca =
          if i < len_a then
            Char.code a.[i]
          else
            0
      in
      let cb =
          if i < len_b then
            Char.code b.[i]
          else
            0
      in
      diff := !diff lor (ca lxor cb)
    done;

    !diff = 0
;;

let verify_at
      ?(window = 0)
      (cfg : config)
      ~(timestamp_s : int64)
      ~(code : string)
  : bool
  =
    if window < 0 then invalid_arg "totp: window must be >= 0";

    let base_counter = counter_of_timestamp cfg ~timestamp_s in
    let rec loop delta =
        if delta > window then
          false
        else (
          let candidate_counter = Int64.add base_counter (Int64.of_int delta) in
          if
            Int64.compare candidate_counter 0L >= 0
            && equal_code_ct code (hotp_code cfg ~counter:candidate_counter)
          then
            true
          else
            loop (delta + 1)
        )
    in
    loop (-window)
;;

let verify_now
      ?(window = 0)
      (cfg : config)
      ~(now_s : unit -> int64)
      ~(code : string)
  : bool
  =
    let timestamp_s = now_s () in
    verify_at ~window cfg ~timestamp_s ~code
;;

let%test "hotp_int rfc4226 counters 0..9" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890";
          digits = 6;
          period = 30;
          t0 = 0L;
          algo = SHA_1
        }
    in
    let expected =
        [ 755224;
          287082;
          359152;
          969429;
          338314;
          254676;
          287922;
          162583;
          399871;
          520489
        ]
    in
    List.for_all2
      (fun counter code -> hotp_int cfg ~counter:(Int64.of_int counter) = code)
      [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9 ]
      expected
;;

let%test "totp_at rfc6238 sha1 vectors" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890";
          digits = 8;
          period = 30;
          t0 = 0L;
          algo = SHA_1
        }
    in
    List.for_all
      (fun (timestamp_s, expected) -> totp_at cfg ~timestamp_s = expected)
      [ (59L, "94287082");
        (1111111109L, "07081804");
        (1111111111L, "14050471");
        (1234567890L, "89005924");
        (2000000000L, "69279037");
        (20000000000L, "65353130")
      ]
;;

let%test "totp_at rfc6238 sha256 vectors" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890123456789012";
          digits = 8;
          period = 30;
          t0 = 0L;
          algo = SHA_256
        }
    in
    List.for_all
      (fun (timestamp_s, expected) -> totp_at cfg ~timestamp_s = expected)
      [ (59L, "46119246");
        (1111111109L, "68084774");
        (1111111111L, "67062674");
        (1234567890L, "91819424");
        (2000000000L, "90698825");
        (20000000000L, "77737706")
      ]
;;

let%test "verify_at exact match and window behavior" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890";
          digits = 8;
          period = 30;
          t0 = 0L;
          algo = SHA_1
        }
    in
    let code_at_59 = "94287082" in
    verify_at cfg ~timestamp_s:59L ~code:code_at_59
    && (not (verify_at cfg ~timestamp_s:61L ~code:code_at_59))
    && verify_at ~window:1 cfg ~timestamp_s:61L ~code:code_at_59
    && not (verify_at ~window:1 cfg ~timestamp_s:59L ~code:"00000000")
;;
