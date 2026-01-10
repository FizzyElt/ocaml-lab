open Core
open Key_schedule
open Variant

let encrypt_block_with_keys
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

    let state = ref (add_round_key block ~round_key:(key_of_round 0)) in
    for i = 1 to rounds - 1 do
      state
      := !state
         |> sub_bytes
         |> shift_rows
         |> mix_columns
         |> add_round_key ~round_key:(key_of_round i)
    done;

    (* final round *)
    !state
    |> sub_bytes
    |> shift_rows
    |> add_round_key ~round_key:(key_of_round rounds)
;;

let encrypt_block ~(variant : variant) (block : bytes) (key : bytes) : bytes =
    let keys = key_expansion ~variant key in

    encrypt_block_with_keys ~variant block keys
;;

let pkcs7_pad (data : bytes) =
    let pad_len = 16 - (Bytes.length data mod 16) in

    if pad_len = 16 then
      Bytes.cat data (Bytes.make 16 (Char.chr 16))
    else
      Bytes.cat data (Bytes.make pad_len (Char.chr pad_len))
;;

let encrypt_cbc ~(variant : variant) (data : bytes) (key : bytes) (iv : bytes)
  : bytes
  =
    let padded = pkcs7_pad data in

    let keys = key_expansion ~variant key in
    let prev = ref iv in

    let out = Bytes.copy padded in

    let block = Bytes.create 16 in
    for i = 0 to (Bytes.length padded / 16) - 1 do
      Bytes.blit padded (i * 16) block 0 16;
      let x = xor_bytes block !prev in
      let c = encrypt_block_with_keys ~variant x keys in

      Bytes.blit c 0 out (i * 16) 16;
      prev := c
    done;
    out
;;

(* 
================== 
=                = 
=   test block   = 
=                = 
================== 
*)
open Codec
let%test "encrypt_block" =
    let key = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt = Hex.to_bytes "00112233445566778899aabbccddeeff" in
    let ct = encrypt_block ~variant:Aes_128 pt key in

    let exp = Hex.to_bytes "69c4e0d86a7b0430d8cdb78070b4c55a" in

    exp = ct
;;

let%test "encrypt_cbc: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    let ct = encrypt_cbc ~variant:Aes_128 pt key iv in
    (* ignore last 16 bytes *)
    let ct_prefix = Bytes.sub ct 0 64 in

    let exp =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    in

    exp = ct_prefix
;;

let%test "encrypt_cbc: pt.length mod 16 <> 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in
    let ct = encrypt_cbc ~variant:Aes_128 pt key iv in

    let exp =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295162c509bd396148c7ce205978abae9ee61"
    in

    exp = ct
;;
