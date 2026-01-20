open Hmac

let hash_len = 32

let extract ~(salt : bytes) ~(ikm : bytes) =
    let salt =
        if Bytes.length salt = 0 then
          Bytes.create hash_len
        else
          salt
    in
    hmac_bytes ikm ~key:salt
;;

let expand (prk : bytes) ~(info : bytes) ~(len : int) =
    if len < 0 then invalid_arg "hkdf: negative length";

    let max_len = 255 * hash_len in

    if len > max_len then invalid_arg "hkdf: length too large";

    let blocks = (len + hash_len - 1) / hash_len in
    let out = Bytes.create len in

    let ti = ref (Bytes.create 0) in
    let out_pos = ref 0 in

    for i = 1 to blocks do
      let ctr = Bytes.make 1 (Char.chr i) in
      let data = Bytes.concat Bytes.empty [ !ti; info; ctr ] in
      ti := hmac_bytes data ~key:prk;

      let take = min hash_len (len - !out_pos) in

      Bytes.blit !ti 0 out !out_pos take;

      out_pos := !out_pos + take
    done;

    out
;;

let derive (ikm : bytes) ~(salt : bytes) ~(info : bytes) ~(len : int) : bytes =
    let prk = extract ~salt ~ikm in
    expand prk ~info ~len
;;

open Codec

let derive_hex
      (ikm_hex : string)
      ~(salt_hex : string)
      ~(info : string)
      ~(len : int)
  : string
  =
    let salt = Hex.to_bytes salt_hex in
    let ikm = Hex.to_bytes ikm_hex in
    let info = Bytes.of_string info in
    Hex.of_bytes (derive ~info ~salt ikm ~len)
;;

let%test "hkdf-sha256 rfc5869 tc1 extract" =
    let ikm = Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let salt = Hex.to_bytes "000102030405060708090a0b0c" in
    let prk = extract ~salt ~ikm in
    Hex.of_bytes prk
    = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
;;

let%test "hkdf-sha256 rfc5869 tc1 expand" =
    let prk =
        Hex.to_bytes
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    in
    let info = Hex.to_bytes "f0f1f2f3f4f5f6f7f8f9" in
    let okm = expand prk ~info ~len:42 in
    Hex.of_bytes okm
    = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
;;

let%test "hkdf-sha256 rfc5869 tc1 derive" =
    let ikm = Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let salt = Hex.to_bytes "000102030405060708090a0b0c" in
    let info = Hex.to_bytes "f0f1f2f3f4f5f6f7f8f9" in
    let okm = derive ikm ~info ~salt ~len:42 in
    Hex.of_bytes okm
    = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
;;
