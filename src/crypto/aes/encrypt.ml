open Codec

type expanded_key =
  { keys : bytes array;
    rounds : int
  }

module Table = struct
  (* 預計算的 S-box *)
  let sbox =
      [| 0x63;
         0x7c;
         0x77;
         0x7b;
         0xf2;
         0x6b;
         0x6f;
         0xc5;
         0x30;
         0x01;
         0x67;
         0x2b;
         0xfe;
         0xd7;
         0xab;
         0x76;
         0xca;
         0x82;
         0xc9;
         0x7d;
         0xfa;
         0x59;
         0x47;
         0xf0;
         0xad;
         0xd4;
         0xa2;
         0xaf;
         0x9c;
         0xa4;
         0x72;
         0xc0;
         0xb7;
         0xfd;
         0x93;
         0x26;
         0x36;
         0x3f;
         0xf7;
         0xcc;
         0x34;
         0xa5;
         0xe5;
         0xf1;
         0x71;
         0xd8;
         0x31;
         0x15;
         0x04;
         0xc7;
         0x23;
         0xc3;
         0x18;
         0x96;
         0x05;
         0x9a;
         0x07;
         0x12;
         0x80;
         0xe2;
         0xeb;
         0x27;
         0xb2;
         0x75;
         0x09;
         0x83;
         0x2c;
         0x1a;
         0x1b;
         0x6e;
         0x5a;
         0xa0;
         0x52;
         0x3b;
         0xd6;
         0xb3;
         0x29;
         0xe3;
         0x2f;
         0x84;
         0x53;
         0xd1;
         0x00;
         0xed;
         0x20;
         0xfc;
         0xb1;
         0x5b;
         0x6a;
         0xcb;
         0xbe;
         0x39;
         0x4a;
         0x4c;
         0x58;
         0xcf;
         0xd0;
         0xef;
         0xaa;
         0xfb;
         0x43;
         0x4d;
         0x33;
         0x85;
         0x45;
         0xf9;
         0x02;
         0x7f;
         0x50;
         0x3c;
         0x9f;
         0xa8;
         0x51;
         0xa3;
         0x40;
         0x8f;
         0x92;
         0x9d;
         0x38;
         0xf5;
         0xbc;
         0xb6;
         0xda;
         0x21;
         0x10;
         0xff;
         0xf3;
         0xd2;
         0xcd;
         0x0c;
         0x13;
         0xec;
         0x5f;
         0x97;
         0x44;
         0x17;
         0xc4;
         0xa7;
         0x7e;
         0x3d;
         0x64;
         0x5d;
         0x19;
         0x73;
         0x60;
         0x81;
         0x4f;
         0xdc;
         0x22;
         0x2a;
         0x90;
         0x88;
         0x46;
         0xee;
         0xb8;
         0x14;
         0xde;
         0x5e;
         0x0b;
         0xdb;
         0xe0;
         0x32;
         0x3a;
         0x0a;
         0x49;
         0x06;
         0x24;
         0x5c;
         0xc2;
         0xd3;
         0xac;
         0x62;
         0x91;
         0x95;
         0xe4;
         0x79;
         0xe7;
         0xc8;
         0x37;
         0x6d;
         0x8d;
         0xd5;
         0x4e;
         0xa9;
         0x6c;
         0x56;
         0xf4;
         0xea;
         0x65;
         0x7a;
         0xae;
         0x08;
         0xba;
         0x78;
         0x25;
         0x2e;
         0x1c;
         0xa6;
         0xb4;
         0xc6;
         0xe8;
         0xdd;
         0x74;
         0x1f;
         0x4b;
         0xbd;
         0x8b;
         0x8a;
         0x70;
         0x3e;
         0xb5;
         0x66;
         0x48;
         0x03;
         0xf6;
         0x0e;
         0x61;
         0x35;
         0x57;
         0xb9;
         0x86;
         0xc1;
         0x1d;
         0x9e;
         0xe1;
         0xf8;
         0x98;
         0x11;
         0x69;
         0xd9;
         0x8e;
         0x94;
         0x9b;
         0x1e;
         0x87;
         0xe9;
         0xce;
         0x55;
         0x28;
         0xdf;
         0x8c;
         0xa1;
         0x89;
         0x0d;
         0xbf;
         0xe6;
         0x42;
         0x68;
         0x41;
         0x99;
         0x2d;
         0x0f;
         0xb0;
         0x54;
         0xbb;
         0x16
      |]
  ;;

  (* 反向 S-box，用於解密 *)
  let inv_sbox =
      [| 0x52;
         0x09;
         0x6a;
         0xd5;
         0x30;
         0x36;
         0xa5;
         0x38;
         0xbf;
         0x40;
         0xa3;
         0x9e;
         0x81;
         0xf3;
         0xd7;
         0xfb;
         0x7c;
         0xe3;
         0x39;
         0x82;
         0x9b;
         0x2f;
         0xff;
         0x87;
         0x34;
         0x8e;
         0x43;
         0x44;
         0xc4;
         0xde;
         0xe9;
         0xcb;
         0x54;
         0x7b;
         0x94;
         0x32;
         0xa6;
         0xc2;
         0x23;
         0x3d;
         0xee;
         0x4c;
         0x95;
         0x0b;
         0x42;
         0xfa;
         0xc3;
         0x4e;
         0x08;
         0x2e;
         0xa1;
         0x66;
         0x28;
         0xd9;
         0x24;
         0xb2;
         0x76;
         0x5b;
         0xa2;
         0x49;
         0x6d;
         0x8b;
         0xd1;
         0x25;
         0x72;
         0xf8;
         0xf6;
         0x64;
         0x86;
         0x68;
         0x98;
         0x16;
         0xd4;
         0xa4;
         0x5c;
         0xcc;
         0x5d;
         0x65;
         0xb6;
         0x92;
         0x6c;
         0x70;
         0x48;
         0x50;
         0xfd;
         0xed;
         0xb9;
         0xda;
         0x5e;
         0x15;
         0x46;
         0x57;
         0xa7;
         0x8d;
         0x9d;
         0x84;
         0x90;
         0xd8;
         0xab;
         0x00;
         0x8c;
         0xbc;
         0xd3;
         0x0a;
         0xf7;
         0xe4;
         0x58;
         0x05;
         0xb8;
         0xb3;
         0x45;
         0x06;
         0xd0;
         0x2c;
         0x1e;
         0x8f;
         0xca;
         0x3f;
         0x0f;
         0x02;
         0xc1;
         0xaf;
         0xbd;
         0x03;
         0x01;
         0x13;
         0x8a;
         0x6b;
         0x3a;
         0x91;
         0x11;
         0x41;
         0x4f;
         0x67;
         0xdc;
         0xea;
         0x97;
         0xf2;
         0xcf;
         0xce;
         0xf0;
         0xb4;
         0xe6;
         0x73;
         0x96;
         0xac;
         0x74;
         0x22;
         0xe7;
         0xad;
         0x35;
         0x85;
         0xe2;
         0xf9;
         0x37;
         0xe8;
         0x1c;
         0x75;
         0xdf;
         0x6e;
         0x47;
         0xf1;
         0x1a;
         0x71;
         0x1d;
         0x29;
         0xc5;
         0x89;
         0x6f;
         0xb7;
         0x62;
         0x0e;
         0xaa;
         0x18;
         0xbe;
         0x1b;
         0xfc;
         0x56;
         0x3e;
         0x4b;
         0xc6;
         0xd2;
         0x79;
         0x20;
         0x9a;
         0xdb;
         0xc0;
         0xfe;
         0x78;
         0xcd;
         0x5a;
         0xf4;
         0x1f;
         0xdd;
         0xa8;
         0x33;
         0x88;
         0x07;
         0xc7;
         0x31;
         0xb1;
         0x12;
         0x10;
         0x59;
         0x27;
         0x80;
         0xec;
         0x5f;
         0x60;
         0x51;
         0x7f;
         0xa9;
         0x19;
         0xb5;
         0x4a;
         0x0d;
         0x2d;
         0xe5;
         0x7a;
         0x9f;
         0x93;
         0xc9;
         0x9c;
         0xef;
         0xa0;
         0xe0;
         0x3b;
         0x4d;
         0xae;
         0x2a;
         0xf5;
         0xb0;
         0xc8;
         0xeb;
         0xbb;
         0x3c;
         0x83;
         0x53;
         0x99;
         0x61;
         0x17;
         0x2b;
         0x04;
         0x7e;
         0xba;
         0x77;
         0xd6;
         0x26;
         0xe1;
         0x69;
         0x14;
         0x63;
         0x55;
         0x21;
         0x0c;
         0x7d
      |]
  ;;

  let rcon = [| 0x01; 0x02; 0x04; 0x08; 0x10; 0x20; 0x40; 0x80; 0x1b; 0x36 |]
end

module Core = struct
  open Table
  let sub_bytes (state : bytes) : bytes =
      let result = Bytes.copy state in
      for i = 0 to 15 do
        let byte = Bytes.get_uint8 state i in
        Bytes.set_uint8 result i sbox.(byte)
      done;

      result
  ;;

  let shift_rows (state : bytes) : bytes =
      let result = Bytes.create 16 in

      (* Row 0 *)
      Bytes.set result 0 (Bytes.get state 0);
      Bytes.set result 4 (Bytes.get state 4);
      Bytes.set result 8 (Bytes.get state 8);
      Bytes.set result 12 (Bytes.get state 12);

      (* Row 1: <- 1 *)
      Bytes.set result 1 (Bytes.get state 5);
      Bytes.set result 5 (Bytes.get state 9);
      Bytes.set result 9 (Bytes.get state 13);
      Bytes.set result 13 (Bytes.get state 1);

      (* Row 2: <- 2 *)
      Bytes.set result 2 (Bytes.get state 10);
      Bytes.set result 6 (Bytes.get state 14);
      Bytes.set result 10 (Bytes.get state 2);
      Bytes.set result 14 (Bytes.get state 6);

      (* Row 3: <- 3 *)
      Bytes.set result 3 (Bytes.get state 15);
      Bytes.set result 7 (Bytes.get state 3);
      Bytes.set result 11 (Bytes.get state 7);
      Bytes.set result 15 (Bytes.get state 11);

      result
  ;;

  let xtime (x : int) : int =
      let x = x land 0xff in
      let shifted = (x lsl 1) land 0xff in
      if x land 0x80 <> 0 then
        shifted lxor 0x1b
      else
        shifted
  ;;

  let mul2 (x : int) : int = xtime x

  let mul3 (x : int) : int = mul2 x lxor x

  let mix_column (a0 : int) (a1 : int) (a2 : int) (a3 : int)
    : int * int * int * int
    =
      let b0 = mul2 a0 lxor mul3 a1 lxor a2 lxor a3 in
      let b1 = a0 lxor mul2 a1 lxor mul3 a2 lxor a3 in
      let b2 = a0 lxor a1 lxor mul2 a2 lxor mul3 a3 in
      let b3 = mul3 a0 lxor a1 lxor a2 lxor mul2 a3 in
      (b0, b1, b2, b3)
  ;;

  let mix_columns (state : bytes) : bytes =
      let result = Bytes.copy state in
      for c = 0 to 3 do
        let i = c * 4 in
        let a0 = Bytes.get_uint8 state (i + 0) in
        let a1 = Bytes.get_uint8 state (i + 1) in
        let a2 = Bytes.get_uint8 state (i + 2) in
        let a3 = Bytes.get_uint8 state (i + 3) in

        let (b0, b1, b2, b3) = mix_column a0 a1 a2 a3 in

        Bytes.set_uint8 result (i + 0) b0;
        Bytes.set_uint8 result (i + 1) b1;
        Bytes.set_uint8 result (i + 2) b2;
        Bytes.set_uint8 result (i + 3) b3
      done;
      result
  ;;

  let add_round_key (state : bytes) ~(round_key : bytes) : bytes =
      let result = Bytes.copy state in
      for i = 0 to 15 do
        let s = Bytes.get_uint8 state i in
        let k = Bytes.get_uint8 round_key i in
        Bytes.set_uint8 result i (s lxor k)
      done;
      result
  ;;
end

module KeySchedule = struct
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
end

open Core
open KeySchedule

let encrypt_block (block : bytes) (key : bytes) : bytes =
    let round_key_of_words = key_expansion key |> round_key_of_words in

    let state = ref (add_round_key block ~round_key:(round_key_of_words 0)) in
    for i = 1 to 9 do
      state
      := !state
         |> sub_bytes
         |> shift_rows
         |> mix_columns
         |> add_round_key ~round_key:(round_key_of_words i)
    done;

    (* final round *)
    !state
    |> sub_bytes
    |> shift_rows
    |> add_round_key ~round_key:(round_key_of_words 10)
;;

let pkcs7_pad (data : bytes) =
    let pad_len = 16 - (Bytes.length data mod 16) in

    if pad_len = 16 then
      Bytes.cat data (Bytes.make 16 (Char.chr 16))
    else
      Bytes.cat data (Bytes.make pad_len (Char.chr pad_len))
;;

let xor_bytes (a : bytes) (b : bytes) : bytes =
    let len = Bytes.length a in
    if Bytes.length b <> len then invalid_arg "xor_bytes: length mismatch";
    let out = Bytes.create len in
    for i = 0 to len - 1 do
      let v = Bytes.get_uint8 a i lxor Bytes.get_uint8 b i in
      Bytes.set_uint8 out i v
    done;
    out
;;

let encrypt_cbc (data : bytes) (key : bytes) (iv : bytes) : bytes =
    let padded = pkcs7_pad data in
    let prev = ref iv in

    let out = Bytes.copy padded in

    let block = Bytes.create 16 in
    for i = 0 to (Bytes.length padded / 16) - 1 do
      Bytes.blit padded (i * 16) block 0 16;
      let x = xor_bytes block !prev in
      let c = encrypt_block x key in

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

let%test "encrypt_block" =
    let key = Hex.bytes_of_hex "000102030405060708090a0b0c0d0e0f" in
    let pt = Hex.bytes_of_hex "00112233445566778899aabbccddeeff" in
    let ct = encrypt_block pt key in

    let exp = Hex.bytes_of_hex "69c4e0d86a7b0430d8cdb78070b4c55a" in

    exp = ct
;;

let%test "encrypt_cbc: pt.length mod 16 = 0" =
    let key = Hex.bytes_of_hex "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.bytes_of_hex "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.bytes_of_hex
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    let ct = encrypt_cbc pt key iv in
    (* ignore last 16 bytes *)
    let ct_prefix = Bytes.sub ct 0 64 in

    let exp =
        Hex.bytes_of_hex
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    in

    exp = ct_prefix
;;

let%test "encrypt_cbc: pt.length mod 16 <> 0" =
    let key = Hex.bytes_of_hex "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.bytes_of_hex "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.bytes_of_hex
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in
    let ct = encrypt_cbc pt key iv in

    let exp =
        Hex.bytes_of_hex
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295162c509bd396148c7ce205978abae9ee61"
    in

    exp = ct
;;
