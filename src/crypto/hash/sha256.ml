open Codec

type word = int32

module Int32_Infix = struct
  open Int32
  let ( land ) = logand
  let ( lor ) = logor
  let ( lxor ) = logxor
  let lnot = lognot
  let ( lsl ) = shift_left
  let ( lsr ) = shift_right_logical
end

open Int32_Infix

let pad_message (data : bytes) : bytes =
    let len = Bytes.length data in
    let bit_len = Int64.mul (Int64.of_int len) 8L in
    let pad_zero_len = (64 - ((len + 1 + 8) mod 64)) mod 64 in
    let total_len = len + 1 + pad_zero_len + 8 in
    let out = Bytes.create total_len in

    Bytes.blit data 0 out 0 len;
    Bytes.set out len '\x80';
    Bytes.set_int64_be out (total_len - 8) bit_len;

    out
;;

let rotr (x : word) (n : int) : word = (x lsr n) lor (x lsl (32 - n))

let ch (x : word) (y : word) (z : word) : word = x land y lxor (lnot x land z)

let maj (x : word) (y : word) (z : word) : word =
    x land y lxor (x land z) lxor (y land z)
;;

let big_sigma0 (x : word) : word = rotr x 2 lxor rotr x 13 lxor rotr x 22

let big_sigma1 (x : word) : word = rotr x 6 lxor rotr x 11 lxor rotr x 25

let small_sigma0 (x : word) : word = rotr x 7 lxor rotr x 18 lxor (x lsr 3)

let small_sigma1 (x : word) : word = rotr x 17 lxor rotr x 19 lxor (x lsr 10)

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
        w.(i) <- Bytes.get_int32_be padded (base + (i * 4))
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
              !h
              |> add (big_sigma1 !e)
              |> add (ch !e !f !g)
              |> add k.(i)
              |> add w.(i) )
        in
        let t2 = Int32.(big_sigma0 !a |> add (maj !a !b !c)) in
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
    Bytes.set_int32_be out 0 !h0;
    Bytes.set_int32_be out 4 !h1;
    Bytes.set_int32_be out 8 !h2;
    Bytes.set_int32_be out 12 !h3;
    Bytes.set_int32_be out 16 !h4;
    Bytes.set_int32_be out 20 !h5;
    Bytes.set_int32_be out 24 !h6;
    Bytes.set_int32_be out 28 !h7;
    out
;;

let digest_string_hex (s : string) : string =
    Hex.of_bytes (digest_bytes (Bytes.of_string s))
;;

let%test "sha256 empty" =
    digest_string_hex ""
    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
;;

let%test "sha256 abc" =
    digest_string_hex "abc"
    = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
;;

let%test "sha256 long message" =
    digest_string_hex "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
;;

let%test "sha256 quick brown fox" =
    digest_string_hex "The quick brown fox jumps over the lazy dog"
    = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
;;
