open Util.Bytes_util

(* ref: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf page 5 *)
(* algorithm: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf *)

let hmac_bytes (msg : bytes) ~(key : bytes) =
    (* sha 256 hmac block size 512 bits = 64 bytes *)
    let block_size = 64 in
    let key_len = Bytes.length key in
    let key' =
        if key_len > block_size then
          Bytes.cat (Sha256.digest_bytes key) (Bytes.create (block_size - 32))
        else
          Bytes.cat key (Bytes.create (block_size - key_len))
    in

    let o_key_pad = xor_bytes (Bytes.make block_size '\x5c') key' in
    let i_key_pad = xor_bytes (Bytes.make block_size '\x36') key' in

    Sha256.digest_bytes
      (Bytes.cat o_key_pad (Sha256.digest_bytes (Bytes.cat i_key_pad msg)))
;;

let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) =
    let computed = hmac_bytes msg ~key in
    equal_bytes_ct computed mac
;;

(* HMAC-SHA256 over raw strings; returns lowercase hex string. *)
let hmac (msg : string) ~(key : string) =
    let msg_bytes = Bytes.of_string msg in
    let key_bytes = Bytes.of_string key in
    hmac_bytes msg_bytes ~key:key_bytes |> Codec.Hex.of_bytes
;;

let hmac_verify (mac : string) ~(key : string) ~(msg : string) =
    let computed = hmac msg ~key in
    try
      equal_bytes_ct (Codec.Hex.to_bytes mac) (Codec.Hex.to_bytes computed)
    with
    | _ -> false
;;

let%test "hmac-sha256 rfc4231 tc1" =
    let key = Codec.Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let msg = Bytes.of_string "Hi There" in
    let mac = hmac_bytes msg ~key in
    Codec.Hex.of_bytes mac
    = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
;;

let%test "hmac-sha256 rfc4231 tc2" =
    let key = Bytes.of_string "Jefe" in
    let msg = Bytes.of_string "what do ya want for nothing?" in
    let mac = hmac_bytes msg ~key in
    Codec.Hex.of_bytes mac
    = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
;;

let%test "hmac-sha256 rfc4231 tc3" =
    let key = Codec.Hex.to_bytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
    let msg =
        Codec.Hex.to_bytes
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    in
    let mac = hmac_bytes msg ~key in
    Codec.Hex.of_bytes mac
    = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
;;

let%test "hmac-sha256 rfc4231 tc4" =
    let key =
        Codec.Hex.to_bytes "0102030405060708090a0b0c0d0e0f10111213141516171819"
    in
    let msg =
        Codec.Hex.to_bytes
          "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    in
    let mac = hmac_bytes msg ~key in
    Codec.Hex.of_bytes mac
    = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
;;
