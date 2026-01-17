type word = int32

let ( &&& ) = Int32.logand
let ( ||| ) = Int32.logor
let ( ^^^ ) = Int32.logxor
let ( ~~~ ) = Int32.lognot

let ( >> ) = Int32.shift_right_logical
let ( << ) = Int32.shift_left

let pad_message (data : bytes) : bytes =
    let len = Bytes.length data in
    let bit_len = Int64.mul (Int64.of_int len) 8L in
    let pad_zero_len = (64 - ((len + 1 + 8) mod 64)) mod 64 in
    let total_len = len + 1 + pad_zero_len + 8 in
    let out = Bytes.create total_len in

    Bytes.blit data 0 out 0 len;
    Bytes.set out len '\x80';

    for i = 0 to 7 do
      let shift = (7 - i) * 8 in
      let byte = Int64.(to_int (logand (shift_right bit_len shift) 0xffL)) in
      Bytes.set out (total_len - 8 + i) (Char.chr byte)
    done;
    out
;;

let rotr (x : word) (n : int) : word = x >> n ||| (x << 32 - n)

let ch (x : word) (y : word) (z : word) : word = (x &&& y) ^^^ (~~~x &&& z)

let maj (x : word) (y : word) (z : word) : word =
    (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)
;;

let big_sigma0 (x : word) : word = rotr x 2 ^^^ rotr x 13 ^^^ rotr x 22

let big_sigma1 (x : word) : word = rotr x 6 ^^^ rotr x 11 ^^^ rotr x 25

let small_sigma0 (x : word) : word = rotr x 7 ^^^ rotr x 18 ^^^ (x >> 3)

let small_sigma1 (x : word) : word = rotr x 17 ^^^ rotr x 19 ^^^ (x >> 10)

let k : word array =
    [| 0x428a2f98l;
       0x71374491l;
       0xb5c0fbcfl;
       0xe9b5dba5l;
       0x3956c25bl;
       0x59f111f1l;
       0x923f82a4l;
       0xab1c5ed5l;
       0xd807aa98l;
       0x12835b01l;
       0x243185bel;
       0x550c7dc3l;
       0x72be5d74l;
       0x80deb1fel;
       0x9bdc06a7l;
       0xc19bf174l;
       0xe49b69c1l;
       0xefbe4786l;
       0x0fc19dc6l;
       0x240ca1ccl;
       0x2de92c6fl;
       0x4a7484aal;
       0x5cb0a9dcl;
       0x76f988dal;
       0x983e5152l;
       0xa831c66dl;
       0xb00327c8l;
       0xbf597fc7l;
       0xc6e00bf3l;
       0xd5a79147l;
       0x06ca6351l;
       0x14292967l;
       0x27b70a85l;
       0x2e1b2138l;
       0x4d2c6dfcl;
       0x53380d13l;
       0x650a7354l;
       0x766a0abbl;
       0x81c2c92el;
       0x92722c85l;
       0xa2bfe8a1l;
       0xa81a664bl;
       0xc24b8b70l;
       0xc76c51a3l;
       0xd192e819l;
       0xd6990624l;
       0xf40e3585l;
       0x106aa070l;
       0x19a4c116l;
       0x1e376c08l;
       0x2748774cl;
       0x34b0bcb5l;
       0x391c0cb3l;
       0x4ed8aa4al;
       0x5b9cca4fl;
       0x682e6ff3l;
       0x748f82eel;
       0x78a5636fl;
       0x84c87814l;
       0x8cc70208l;
       0x90befffal;
       0xa4506cebl;
       0xbef9a3f7l;
       0xc67178f2l
    |]
;;

let get_be32 (b : bytes) (off : int) : word =
    let b0 = Int32.of_int (Char.code (Bytes.get b off)) in
    let b1 = Int32.of_int (Char.code (Bytes.get b (off + 1))) in
    let b2 = Int32.of_int (Char.code (Bytes.get b (off + 2))) in
    let b3 = Int32.of_int (Char.code (Bytes.get b (off + 3))) in
    b0 << 24 ||| b1 << 16 ||| b2 << 8 ||| b3
;;

let put_be32 (b : bytes) (off : int) (x : word) : unit =
    Bytes.set b off (x >> 24 &&& 0xffl |> Int32.to_int |> Char.chr);
    Bytes.set b (off + 1) (x >> 16 &&& 0xffl |> Int32.to_int |> Char.chr);
    Bytes.set b (off + 2) (x >> 8 &&& 0xffl |> Int32.to_int |> Char.chr);
    Bytes.set b (off + 3) (x &&& 0xffl |> Int32.to_int |> Char.chr)
;;

let digest_bytes (data : bytes) : bytes =
    let h0 = ref 0x6a09e667l in
    let h1 = ref 0xbb67ae85l in
    let h2 = ref 0x3c6ef372l in
    let h3 = ref 0xa54ff53al in
    let h4 = ref 0x510e527fl in
    let h5 = ref 0x9b05688cl in
    let h6 = ref 0x1f83d9abl in
    let h7 = ref 0x5be0cd19l in

    let padded = pad_message data in
    let blocks = Bytes.length padded / 64 in
    let w = Array.make 64 0l in

    for bi = 0 to blocks - 1 do
      let base = bi * 64 in
      for i = 0 to 15 do
        w.(i) <- get_be32 padded (base + (i * 4))
      done;
      for i = 16 to 63 do
        let s0 = small_sigma0 w.(i - 15) in
        let s1 = small_sigma1 w.(i - 2) in
        w.(i) <- Int32.(w.(i - 16) |> add s0 |> add w.(i - 7) |> add s1)
      done;

      let a = ref !h0 in
      let b = ref !h1 in
      let c = ref !h2 in
      let d = ref !h3 in
      let e = ref !h4 in
      let f = ref !h5 in
      let g = ref !h6 in
      let h = ref !h7 in

      for i = 0 to 63 do
        let t1 =
            Int32.(
              add (add (add (add !h (big_sigma1 !e)) (ch !e !f !g)) k.(i)) w.(i) )
        in
        let t2 = Int32.(add (big_sigma0 !a) (maj !a !b !c)) in
        h := !g;
        g := !f;
        f := !e;
        e := Int32.add !d t1;
        d := !c;
        c := !b;
        b := !a;
        a := Int32.add t1 t2
      done;

      h0 := Int32.add !h0 !a;
      h1 := Int32.add !h1 !b;
      h2 := Int32.add !h2 !c;
      h3 := Int32.add !h3 !d;
      h4 := Int32.add !h4 !e;
      h5 := Int32.add !h5 !f;
      h6 := Int32.add !h6 !g;
      h7 := Int32.add !h7 !h
    done;

    let out = Bytes.create 32 in
    put_be32 out 0 !h0;
    put_be32 out 4 !h1;
    put_be32 out 8 !h2;
    put_be32 out 12 !h3;
    put_be32 out 16 !h4;
    put_be32 out 20 !h5;
    put_be32 out 24 !h6;
    put_be32 out 28 !h7;
    out
;;
