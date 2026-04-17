open Hash

type algo =
  | SHA_1
  | SHA_256
  | SHA_512

type config =
  { secret : bytes;
    digits : int;
    algo : algo
  }

let default_config (secret : bytes) : config = { secret; digits = 6; algo = SHA_1 }

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
    if cfg.digits <= 0 then invalid_arg "hotp: digits must be > 0";

    let counter_bytes = Bytes.create 8 in
    Bytes.set_int64_be counter_bytes 0 counter;

    let mac = hmac_by_algo cfg counter_bytes in
    let mac_len = Bytes.length mac in

    if mac_len < 20 then invalid_arg "hotp: invalid HMAC length";

    let offset = Char.code (Bytes.get mac (mac_len - 1)) land 0x0f in
    if offset + 3 >= mac_len then invalid_arg "hotp: invalid dynamic offset";

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

let verify_hotp (cfg : config) ~(counter : int64) ~(code : string) : bool =
    equal_code_ct code (hotp_code cfg ~counter)
;;

let%test "hotp_int rfc4226 counters 0..9" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890";
          digits = 6;
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

let%test "verify_hotp exact match" =
    let cfg =
        { secret = Bytes.of_string "12345678901234567890";
          digits = 6;
          algo = SHA_1
        }
    in
    verify_hotp cfg ~counter:0L ~code:"755224"
    && not (verify_hotp cfg ~counter:0L ~code:"000000")
    && not (verify_hotp cfg ~counter:1L ~code:"755224")
;;
