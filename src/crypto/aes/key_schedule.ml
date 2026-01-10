type word = bytes

open Table

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

let key_expansion (key : bytes) : word array =
    if Bytes.length key <> 16 then invalid_arg "AES-128 key must be 16 bytes";
    let w = Array.make 44 (Bytes.create 4) in
    for i = 0 to 3 do
      let word = Bytes.create 4 in
      Bytes.blit key (i * 4) word 0 4;
      w.(i) <- word
    done;

    for i = 4 to 43 do
      let temp = ref w.(i - 1) in
      if i mod 4 = 0 then
        temp := xor_word (sub_word (rot_word !temp)) (rcon_word ((i / 4) - 1));
      w.(i) <- xor_word w.(i - 4) !temp
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
