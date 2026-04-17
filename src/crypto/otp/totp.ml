type config =
  { hotp : Hotp.config;
    period : int;
    t0 : int64
  }

let default_config (secret : bytes) : config =
    { hotp = Hotp.default_config secret; period = 30; t0 = 0L }
;;

let counter_of_timestamp (cfg : config) ~(timestamp_s : int64) : int64 =
    if cfg.period <= 0 then invalid_arg "totp: period must be > 0";

    let delta = Int64.sub timestamp_s cfg.t0 in

    if Int64.compare delta 0L < 0 then
      invalid_arg "totp: timestamp is before t0";

    Int64.div delta (Int64.of_int cfg.period)
;;

let totp_at (cfg : config) ~(timestamp_s : int64) : string =
    let counter = counter_of_timestamp cfg ~timestamp_s in
    Hotp.hotp_code cfg.hotp ~counter
;;

let totp_now (cfg : config) ~(timestamp_s : int64) : string =
    totp_at cfg ~timestamp_s
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
            && Hotp.verify_hotp cfg.hotp ~counter:candidate_counter ~code
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

let%test "totp_at rfc6238 sha1 vectors" =
    let cfg =
        { hotp =
            { Hotp.secret = Bytes.of_string "12345678901234567890";
              digits = 8;
              algo = Hotp.SHA_1
            };
          period = 30;
          t0 = 0L
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
        { hotp =
            { Hotp.secret = Bytes.of_string "12345678901234567890123456789012";
              digits = 8;
              algo = Hotp.SHA_256
            };
          period = 30;
          t0 = 0L
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
        { hotp =
            { Hotp.secret = Bytes.of_string "12345678901234567890";
              digits = 8;
              algo = Hotp.SHA_1
            };
          period = 30;
          t0 = 0L
        }
    in
    let code_at_59 = "94287082" in
    verify_at cfg ~timestamp_s:59L ~code:code_at_59
    && (not (verify_at cfg ~timestamp_s:61L ~code:code_at_59))
    && verify_at ~window:1 cfg ~timestamp_s:61L ~code:code_at_59
    && not (verify_at ~window:1 cfg ~timestamp_s:59L ~code:"00000000")
;;
