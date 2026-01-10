open Core
open Key_schedule
open Variant

let decrypt_block_with_keys
      ~(variant : variant)
      (block : bytes)
      (keys : word array)
  : bytes
  =
    let rounds =
        match variant with
        | Aes_128 -> 10
        | Aes_192 -> 12
        | Aes_256 -> 14
    in
    let key_of_round = round_key_of_words keys in
    let state = ref (add_round_key block ~round_key:(key_of_round rounds)) in

    for i = rounds - 1 downto 1 do
      state
      := !state
         |> inv_shift_rows
         |> inv_sub_bytes
         |> add_round_key ~round_key:(key_of_round i)
         |> inv_mix_columns
    done;

    !state
    |> inv_shift_rows
    |> inv_sub_bytes
    |> add_round_key ~round_key:(key_of_round 0)
;;

let decrypt_block ~(variant : variant) (block : bytes) (key : bytes) : bytes =
    let keys = key_expansion ~variant key in

    decrypt_block_with_keys ~variant block keys
;;

let pkcs7_unpad (data : bytes) : bytes =
    let len = Bytes.length data in
    if len = 0 || len mod 16 <> 0 then invalid_arg "pkcs7_unpad: bad length";
    let pad = Bytes.get_uint8 data (len - 1) in
    if pad = 0 || pad > 16 then invalid_arg "pkcs7_unpad: bad padding";

    for i = len - pad to len - 1 do
      if Bytes.get_uint8 data i <> pad then
        invalid_arg "pkcs7_unpad: bad padding"
    done;
    Bytes.sub data 0 (len - pad)
;;

let decrypt_cbc ~(variant : variant) (ct : bytes) (key : bytes) (iv : bytes)
  : bytes
  =
    if Bytes.length ct mod 16 <> 0 then invalid_arg "decrypt_cbc: length";

    let keys = key_expansion ~variant key in
    let prev = ref iv in
    let out = Bytes.create (Bytes.length ct) in
    let block = Bytes.create 16 in
    for i = 0 to (Bytes.length ct / 16) - 1 do
      Bytes.blit ct (i * 16) block 0 16;
      let p = decrypt_block_with_keys ~variant block keys |> xor_bytes !prev in
      Bytes.blit p 0 out (i * 16) 16;
      prev := Bytes.copy block
    done;

    pkcs7_unpad out
;;

(* 
================== 
=                = 
=   test block   = 
=                = 
================== 
*)
open Codec

let%test "decrypt_block" =
    let key = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let exp = Hex.to_bytes "69c4e0d86a7b0430d8cdb78070b4c55a" in
    let dt = decrypt_block ~variant:Aes_128 exp key in

    let pt = Hex.to_bytes "00112233445566778899aabbccddeeff" in

    pt = dt
;;

let%test "decrypt_cbc: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012"
    in
    let dt = decrypt_cbc ~variant:Aes_128 ct key iv in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    pt = dt
;;

let%test "decrypt_cbc: pt.length mod 16 <> 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295162c509bd396148c7ce205978abae9ee61"
    in
    let dt = decrypt_cbc ~variant:Aes_128 ct key iv in

    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in

    pt = dt
;;
