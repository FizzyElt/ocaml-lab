open Util.Bytes_util

type algo =
  [ `Sha_512
  | `Sha_256
  | `Sha_1
  ]

(* ref: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf page 5 *)
(* algorithm: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf *)
module HmacSha512 = struct
  let hmac_bytes (msg : bytes) ~(key : bytes) : bytes =
      (* sha 512 hmac block size 1024 bits = 128 bytes *)
      let block_size = 128 in
      let key_len = Bytes.length key in
      let key' =
          if key_len > block_size then
            Bytes.cat (Sha512.digest_bytes key) (Bytes.create (block_size - 64))
          else
            Bytes.cat key (Bytes.create (block_size - key_len))
      in

      let o_key_pad = xor_bytes (Bytes.make block_size '\x5c') key' in
      let i_key_pad = xor_bytes (Bytes.make block_size '\x36') key' in

      Sha512.digest_bytes
        (Bytes.cat o_key_pad (Sha512.digest_bytes (Bytes.cat i_key_pad msg)))
  ;;

  let hmac (msg : string) ~(key : string) : string =
      let msg_bytes = Bytes.of_string msg in
      let key_bytes = Bytes.of_string key in
      hmac_bytes msg_bytes ~key:key_bytes |> Codec.Hex.of_bytes
  ;;

  let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) : bool =
      let computed = hmac_bytes msg ~key in
      equal_bytes_ct computed mac
  ;;

  let hmac_verify (mac : string) ~(key : string) ~(msg : string) : bool =
      let computed = hmac msg ~key in
      try
        equal_bytes_ct (Codec.Hex.to_bytes mac) (Codec.Hex.to_bytes computed)
      with
      | _ -> false
  ;;
end

module HmacSha256 = struct
  let hmac_bytes (msg : bytes) ~(key : bytes) : bytes =
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

  let hmac (msg : string) ~(key : string) : string =
      let msg_bytes = Bytes.of_string msg in
      let key_bytes = Bytes.of_string key in
      hmac_bytes msg_bytes ~key:key_bytes |> Codec.Hex.of_bytes
  ;;

  let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) : bool =
      let computed = hmac_bytes msg ~key in
      equal_bytes_ct computed mac
  ;;

  let hmac_verify (mac : string) ~(key : string) ~(msg : string) : bool =
      let computed = hmac msg ~key in
      try
        equal_bytes_ct (Codec.Hex.to_bytes mac) (Codec.Hex.to_bytes computed)
      with
      | _ -> false
  ;;
end

module HmacSha1 = struct
  let hmac_bytes (msg : bytes) ~(key : bytes) : bytes =
      (* sha1 hmac block size 512 bits = 64 bytes *)
      let block_size = 64 in
      let digest_size = 20 in
      let key_len = Bytes.length key in
      let key' =
          if key_len > block_size then
            Bytes.cat
              (Sha1.digest_bytes key)
              (Bytes.create (block_size - digest_size))
          else
            Bytes.cat key (Bytes.create (block_size - key_len))
      in

      let o_key_pad = xor_bytes (Bytes.make block_size '\x5c') key' in
      let i_key_pad = xor_bytes (Bytes.make block_size '\x36') key' in

      Sha1.digest_bytes
        (Bytes.cat o_key_pad (Sha1.digest_bytes (Bytes.cat i_key_pad msg)))
  ;;

  let hmac (msg : string) ~(key : string) : string =
      let msg_bytes = Bytes.of_string msg in
      let key_bytes = Bytes.of_string key in
      hmac_bytes msg_bytes ~key:key_bytes |> Codec.Hex.of_bytes
  ;;

  let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) : bool =
      let computed = hmac_bytes msg ~key in
      equal_bytes_ct computed mac
  ;;

  let hmac_verify (mac : string) ~(key : string) ~(msg : string) : bool =
      let computed = hmac msg ~key in
      try
        equal_bytes_ct (Codec.Hex.to_bytes mac) (Codec.Hex.to_bytes computed)
      with
      | _ -> false
  ;;
end

let hmac_bytes (msg : bytes) ~(key : bytes) ~(algo : algo) : bytes =
    match algo with
    | `Sha_1 -> HmacSha1.hmac_bytes msg ~key
    | `Sha_256 -> HmacSha256.hmac_bytes msg ~key
    | `Sha_512 -> HmacSha512.hmac_bytes msg ~key
;;

let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) ~(algo : algo)
  : bool
  =
    let computed = hmac_bytes msg ~key ~algo in
    equal_bytes_ct computed mac
;;

(* returns lowercase hex string. *)
let hmac (msg : string) ~(key : string) ~(algo : algo) : string =
    let msg_bytes = Bytes.of_string msg in
    let key_bytes = Bytes.of_string key in
    hmac_bytes msg_bytes ~key:key_bytes ~algo |> Codec.Hex.of_bytes
;;

let hmac_verify (mac : string) ~(key : string) ~(msg : string) ~(algo : algo)
  : bool
  =
    let computed = hmac msg ~key ~algo in
    try
      equal_bytes_ct (Codec.Hex.to_bytes mac) (Codec.Hex.to_bytes computed)
    with
    | _ -> false
;;

let%test "hmac-sha256 rfc4231 tc1" =
    let key = Codec.Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let msg = Bytes.of_string "Hi There" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_256 in
    Codec.Hex.of_bytes mac
    = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
;;

let%test "hmac-sha256 rfc4231 tc2" =
    let key = Bytes.of_string "Jefe" in
    let msg = Bytes.of_string "what do ya want for nothing?" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_256 in
    Codec.Hex.of_bytes mac
    = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
;;

let%test "hmac-sha256 rfc4231 tc3" =
    let key = Codec.Hex.to_bytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
    let msg =
        Codec.Hex.to_bytes
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    in
    let mac = hmac_bytes msg ~key ~algo:`Sha_256 in
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
    let mac = hmac_bytes msg ~key ~algo:`Sha_256 in
    Codec.Hex.of_bytes mac
    = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
;;

let%test "hmac-sha512 rfc4231 tc1" =
    let key = Codec.Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let msg = Bytes.of_string "Hi There" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
       daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
;;

let%test "hmac-sha512 rfc4231 tc2" =
    let key = Bytes.of_string "Jefe" in
    let msg = Bytes.of_string "what do ya want for nothing?" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
       9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
;;

let%test "hmac-sha512 rfc4231 tc3" =
    let key = Codec.Hex.to_bytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
    let msg =
        Codec.Hex.to_bytes
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
       bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
;;

let%test "hmac-sha512 rfc4231 tc4" =
    let key =
        Codec.Hex.to_bytes "0102030405060708090a0b0c0d0e0f10111213141516171819"
    in
    let msg =
        Codec.Hex.to_bytes
          "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
       a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
;;
