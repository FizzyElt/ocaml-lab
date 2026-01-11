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
