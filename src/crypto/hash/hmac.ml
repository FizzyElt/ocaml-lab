open Util.Bytes_util

type algo =
  [ `Sha_512
  | `Sha_256
  | `Sha_1
  ]

(* ref: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf page 5 *)
(* algorithm: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf *)
module type DIGEST = sig
  val block_size : int
  val digest_size : int
  val digest_bytes : bytes -> bytes
end

module Make (D : DIGEST) = struct
  let hmac_bytes (msg : bytes) ~(key : bytes) : bytes =
      let key_len = Bytes.length key in
      let key' =
          if key_len > D.block_size then
            Bytes.cat
              (D.digest_bytes key)
              (Bytes.create (D.block_size - D.digest_size))
          else
            Bytes.cat key (Bytes.create (D.block_size - key_len))
      in

      let o_key_pad = xor_bytes (Bytes.make D.block_size '\x5c') key' in
      let i_key_pad = xor_bytes (Bytes.make D.block_size '\x36') key' in

      D.digest_bytes
        (Bytes.cat o_key_pad (D.digest_bytes (Bytes.cat i_key_pad msg)))
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

module DigestSha1 : DIGEST = struct
  let block_size = 64
  let digest_size = 20
  let digest_bytes = Sha1.digest_bytes
end

module DigestSha256 : DIGEST = struct
  let block_size = 64
  let digest_size = 32
  let digest_bytes = Sha256.digest_bytes
end

module DigestSha512 : DIGEST = struct
  let block_size = 128
  let digest_size = 64
  let digest_bytes = Sha512.digest_bytes
end

module HmacSha1 = Make (struct
    let block_size = 64
    let digest_size = 20
    let digest_bytes = Sha1.digest_bytes
  end)

module HmacSha256 = Make (struct
    let block_size = 64
    let digest_size = 32
    let digest_bytes = Sha256.digest_bytes
  end)

module HmacSha512 = Make (struct
    let block_size = 128
    let digest_size = 64
    let digest_bytes = Sha512.digest_bytes
  end)

let digest_size_of_algo = function
  | `Sha_1 -> DigestSha1.digest_size
  | `Sha_256 -> DigestSha256.digest_size
  | `Sha_512 -> DigestSha512.digest_size
;;

let hmac_bytes (msg : bytes) ~(key : bytes) ~(algo : algo) : bytes =
    match algo with
    | `Sha_1 -> HmacSha1.hmac_bytes msg ~key
    | `Sha_256 -> HmacSha256.hmac_bytes msg ~key
    | `Sha_512 -> HmacSha512.hmac_bytes msg ~key
;;

let hmac_verify_bytes (mac : bytes) ~(key : bytes) ~(msg : bytes) ~(algo : algo)
  : bool
  =
    let expected_len = digest_size_of_algo algo in
    if Bytes.length mac <> expected_len then
      false
    else (
      let computed = hmac_bytes msg ~key ~algo in
      equal_bytes_ct computed mac
    )
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
    try
      let mac_bytes = Codec.Hex.to_bytes mac in
      hmac_verify_bytes
        mac_bytes
        ~key:(Bytes.of_string key)
        ~msg:(Bytes.of_string msg)
        ~algo
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
    = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
;;

let%test "hmac-sha512 rfc4231 tc2" =
    let key = Bytes.of_string "Jefe" in
    let msg = Bytes.of_string "what do ya want for nothing?" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
;;

let%test "hmac-sha512 rfc4231 tc3" =
    let key = Codec.Hex.to_bytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
    let msg =
        Codec.Hex.to_bytes
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    in
    let mac = hmac_bytes msg ~key ~algo:`Sha_512 in
    Codec.Hex.of_bytes mac
    = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
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
    = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
;;

let%test "hmac-sha1 rfc2202 tc1" =
    let key = Codec.Hex.to_bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" in
    let msg = Bytes.of_string "Hi There" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_1 in
    Codec.Hex.of_bytes mac = "b617318655057264e28bc0b6fb378c8ef146be00"
;;

let%test "hmac-sha1 rfc2202 tc2" =
    let key = Bytes.of_string "Jefe" in
    let msg = Bytes.of_string "what do ya want for nothing?" in
    let mac = hmac_bytes msg ~key ~algo:`Sha_1 in
    Codec.Hex.of_bytes mac = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
;;

let%test "hmac-sha1 rfc2202 tc3" =
    let key = Codec.Hex.to_bytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
    let msg =
        Array.make 50 "dd"
        |> Array.to_list
        |> String.concat ""
        |> Codec.Hex.to_bytes
    in
    let mac = hmac_bytes msg ~key ~algo:`Sha_1 in
    Codec.Hex.of_bytes mac = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
;;
