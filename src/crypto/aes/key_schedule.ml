open Table
open Variant

type word = bytes

(* rotate word *)
let rot_word (w : word) : word =
    let out = Bytes.create 4 in
    Bytes.set_uint8 out 0 (Bytes.get_uint8 w 1);
    Bytes.set_uint8 out 1 (Bytes.get_uint8 w 2);
    Bytes.set_uint8 out 2 (Bytes.get_uint8 w 3);
    Bytes.set_uint8 out 3 (Bytes.get_uint8 w 0);
    out
;;

(* substitute word *)
let sub_word (w : word) : word =
    let out = Bytes.create 4 in
    for i = 0 to 3 do
      let b = Bytes.get_uint8 w i in
      Bytes.set_uint8 out i sbox.(b)
    done;
    out
;;

(* round constant *)
let rcon_word (i : int) : word =
    let out = Bytes.create 4 in
    Bytes.set_uint8 out 0 rcon.(i);
    Bytes.set_uint8 out 1 0;
    Bytes.set_uint8 out 2 0;
    Bytes.set_uint8 out 3 0;
    out
;;

let xor_word (a : word) (b : word) : word =
    let out = Bytes.create 4 in
    for i = 0 to 3 do
      let v = Bytes.get_uint8 a i lxor Bytes.get_uint8 b i in
      Bytes.set_uint8 out i v
    done;
    out
;;

type params =
  { nk : int;
    nr : int;
    key_len : int
  }

let aes128 = { nk = 4; nr = 10; key_len = 16 }
let aes192 = { nk = 6; nr = 12; key_len = 24 }
let aes256 = { nk = 8; nr = 14; key_len = 32 }

let key_expansion ~(variant : variant) (key : bytes) : word array =
    let params =
        match variant with
        | Aes_128 -> aes128
        | Aes_192 -> aes192
        | Aes_256 -> aes256
    in

    if Bytes.length key <> params.key_len then
      invalid_arg "key_expansion: bad key length";

    let total_words = 4 * (params.nr + 1) in

    let w = Array.make total_words (Bytes.create 4) in

    for i = 0 to params.nk - 1 do
      let word = Bytes.create 4 in
      Bytes.blit key (i * 4) word 0 4;
      w.(i) <- word
    done;

    for i = params.nk to total_words - 1 do
      let temp = ref w.(i - 1) in
      if i mod params.nk = 0 then
        temp
        := xor_word
             (sub_word (rot_word !temp))
             (rcon_word ((i / params.nk) - 1))
      else if params.nk > 6 && i mod params.nk = 4 then
        (* AES-256 special case *)
        temp := sub_word !temp;

      w.(i) <- xor_word w.(i - params.nk) !temp
    done;

    w
;;

let round_key_of_words (w : word array) (round : int) : bytes =
    let out = Bytes.create 16 in
    for i = 0 to 3 do
      let word = w.((round * 4) + i) in
      Bytes.blit word 0 out (i * 4) 4
    done;

    out
;;
