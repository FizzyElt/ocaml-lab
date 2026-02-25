open Codec

(* ref: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf *)

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

let rotl (x : word) (n : int) : word = (x lsl n) lor (x lsr (32 - n))

let f (t : int) (b : word) (c : word) (d : word) : word =
    if t < 20 then
      (b land c) lor (lnot b land d)
    else if t < 40 then
      b lxor c lxor d
    else if t < 60 then
      (b land c) lor (b land d) lor (c land d)
    else
      b lxor c lxor d
;;

let k (t : int) : word =
    if t < 20 then
      0x5a827999l
    else if t < 40 then
      0x6ed9eba1l
    else if t < 60 then
      0x8f1bbcdcl
    else
      0xca62c1d6l
;;

let digest_bytes (data : bytes) : bytes =
    let h0 = ref 0x67452301l in
    let h1 = ref 0xefcdab89l in
    let h2 = ref 0x98badcfel in
    let h3 = ref 0x10325476l in
    let h4 = ref 0xc3d2e1f0l in

    let padded = pad_message data in
    let blocks = Bytes.length padded / 64 in
    let w = Array.make 80 0l in

    for bi = 0 to blocks - 1 do
      let base = bi * 64 in
      for i = 0 to 15 do
        w.(i) <- Bytes.get_int32_be padded (base + (i * 4))
      done;
      for i = 16 to 79 do
        w.(i) <- rotl Int32.(w.(i - 3) lxor w.(i - 8) lxor w.(i - 14) lxor w.(i - 16)) 1
      done;

      let a = ref !h0 in
      let b = ref !h1 in
      let c = ref !h2 in
      let d = ref !h3 in
      let e = ref !h4 in

      for t = 0 to 79 do
        let temp =
            Int32.(
              rotl !a 5
              |> add (f t !b !c !d)
              |> add !e
              |> add (k t)
              |> add w.(t) )
        in
        e := !d;
        d := !c;
        c := rotl !b 30;
        b := !a;
        a := temp
      done;

      h0 := Int32.add !h0 !a;
      h1 := Int32.add !h1 !b;
      h2 := Int32.add !h2 !c;
      h3 := Int32.add !h3 !d;
      h4 := Int32.add !h4 !e
    done;

    let out = Bytes.create 20 in
    Bytes.set_int32_be out 0 !h0;
    Bytes.set_int32_be out 4 !h1;
    Bytes.set_int32_be out 8 !h2;
    Bytes.set_int32_be out 12 !h3;
    Bytes.set_int32_be out 16 !h4;
    out
;;

let digest_string_hex (s : string) : string =
    Hex.of_bytes (digest_bytes (Bytes.of_string s))
;;

let%test "sha1 empty" =
    digest_string_hex "" = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
;;

let%test "sha1 abc" =
    digest_string_hex "abc" = "a9993e364706816aba3e25717850c26c9cd0d89d"
;;

let%test "sha1 long message" =
    digest_string_hex "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
;;

let%test "sha1 quick brown fox" =
    digest_string_hex "The quick brown fox jumps over the lazy dog"
    = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
;;
