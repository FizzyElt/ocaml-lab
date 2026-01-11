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
