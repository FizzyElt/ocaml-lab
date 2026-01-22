open Codec

type word = int64

module Int64_Infix = struct
  open Int64
  let ( land ) = logand
  let ( lor ) = logor
  let ( lxor ) = logxor
  let lnot = lognot
  let ( lsl ) = shift_left
  let ( lsr ) = shift_right_logical
end

open Int64_Infix

let pad_message (data : bytes) : bytes =
    let len = Bytes.length data in
    let bit_len = Int64.mul (Int64.of_int len) 8L in
    let pad_zero_len = (128 - ((len + 1 + 16) mod 128)) mod 128 in
    let total_len = len + 1 + pad_zero_len + 16 in
    let out = Bytes.create total_len in

    Bytes.blit data 0 out 0 len;
    Bytes.set out len '\x80';
    Bytes.set_int64_be out (total_len - 16) 0L;
    Bytes.set_int64_be out (total_len - 8) bit_len;

    out
;;

let rotr (x : word) (n : int) : word = (x lsr n) lor (x lsl (64 - n))

let ch (x : word) (y : word) (z : word) : word = x land y lxor (lnot x land z)

let maj (x : word) (y : word) (z : word) : word =
    x land y lxor (x land z) lxor (y land z)
;;

let big_sigma0 (x : word) : word = rotr x 28 lxor rotr x 34 lxor rotr x 39

let big_sigma1 (x : word) : word = rotr x 14 lxor rotr x 18 lxor rotr x 41

let small_sigma0 (x : word) : word = rotr x 1 lxor rotr x 8 lxor (x lsr 7)

let small_sigma1 (x : word) : word = rotr x 19 lxor rotr x 61 lxor (x lsr 6)

let k : word array =
    [| 0x428a2f98d728ae22L;
       0x7137449123ef65cdL;
       0xb5c0fbcfec4d3b2fL;
       0xe9b5dba58189dbbcL;
       0x3956c25bf348b538L;
       0x59f111f1b605d019L;
       0x923f82a4af194f9bL;
       0xab1c5ed5da6d8118L;
       0xd807aa98a3030242L;
       0x12835b0145706fbeL;
       0x243185be4ee4b28cL;
       0x550c7dc3d5ffb4e2L;
       0x72be5d74f27b896fL;
       0x80deb1fe3b1696b1L;
       0x9bdc06a725c71235L;
       0xc19bf174cf692694L;
       0xe49b69c19ef14ad2L;
       0xefbe4786384f25e3L;
       0x0fc19dc68b8cd5b5L;
       0x240ca1cc77ac9c65L;
       0x2de92c6f592b0275L;
       0x4a7484aa6ea6e483L;
       0x5cb0a9dcbd41fbd4L;
       0x76f988da831153b5L;
       0x983e5152ee66dfabL;
       0xa831c66d2db43210L;
       0xb00327c898fb213fL;
       0xbf597fc7beef0ee4L;
       0xc6e00bf33da88fc2L;
       0xd5a79147930aa725L;
       0x06ca6351e003826fL;
       0x142929670a0e6e70L;
       0x27b70a8546d22ffcL;
       0x2e1b21385c26c926L;
       0x4d2c6dfc5ac42aedL;
       0x53380d139d95b3dfL;
       0x650a73548baf63deL;
       0x766a0abb3c77b2a8L;
       0x81c2c92e47edaee6L;
       0x92722c851482353bL;
       0xa2bfe8a14cf10364L;
       0xa81a664bbc423001L;
       0xc24b8b70d0f89791L;
       0xc76c51a30654be30L;
       0xd192e819d6ef5218L;
       0xd69906245565a910L;
       0xf40e35855771202aL;
       0x106aa07032bbd1b8L;
       0x19a4c116b8d2d0c8L;
       0x1e376c085141ab53L;
       0x2748774cdf8eeb99L;
       0x34b0bcb5e19b48a8L;
       0x391c0cb3c5c95a63L;
       0x4ed8aa4ae3418acbL;
       0x5b9cca4f7763e373L;
       0x682e6ff3d6b2b8a3L;
       0x748f82ee5defb2fcL;
       0x78a5636f43172f60L;
       0x84c87814a1f0ab72L;
       0x8cc702081a6439ecL;
       0x90befffa23631e28L;
       0xa4506cebde82bde9L;
       0xbef9a3f7b2c67915L;
       0xc67178f2e372532bL;
       0xca273eceea26619cL;
       0xd186b8c721c0c207L;
       0xeada7dd6cde0eb1eL;
       0xf57d4f7fee6ed178L;
       0x06f067aa72176fbaL;
       0x0a637dc5a2c898a6L;
       0x113f9804bef90daeL;
       0x1b710b35131c471bL;
       0x28db77f523047d84L;
       0x32caab7b40c72493L;
       0x3c9ebe0a15c9bebcL;
       0x431d67c49c100d4cL;
       0x4cc5d4becb3e42b6L;
       0x597f299cfc657e2aL;
       0x5fcb6fab3ad6faecL;
       0x6c44198c4a475817L
    |]
;;

let digest_bytes (data : bytes) : bytes =
    let h0 = ref 0x6a09e667f3bcc908L in
    let h1 = ref 0xbb67ae8584caa73bL in
    let h2 = ref 0x3c6ef372fe94f82bL in
    let h3 = ref 0xa54ff53a5f1d36f1L in
    let h4 = ref 0x510e527fade682d1L in
    let h5 = ref 0x9b05688c2b3e6c1fL in
    let h6 = ref 0x1f83d9abfb41bd6bL in
    let h7 = ref 0x5be0cd19137e2179L in

    let padded = pad_message data in
    let blocks = Bytes.length padded / 128 in
    let w = Array.make 80 0L in

    for bi = 0 to blocks - 1 do
      let base = bi * 128 in
      for i = 0 to 15 do
        w.(i) <- Bytes.get_int64_be padded (base + (i * 8))
      done;
      for i = 16 to 79 do
        let s0 = small_sigma0 w.(i - 15) in
        let s1 = small_sigma1 w.(i - 2) in
        w.(i) <- Int64.(w.(i - 16) |> add s0 |> add w.(i - 7) |> add s1)
      done;

      let a = ref !h0 in
      let b = ref !h1 in
      let c = ref !h2 in
      let d = ref !h3 in
      let e = ref !h4 in
      let f = ref !h5 in
      let g = ref !h6 in
      let h = ref !h7 in

      for i = 0 to 79 do
        let t1 =
            Int64.(
              !h
              |> add (big_sigma1 !e)
              |> add (ch !e !f !g)
              |> add k.(i)
              |> add w.(i) )
        in
        let t2 = Int64.(big_sigma0 !a |> add (maj !a !b !c)) in
        h := !g;
        g := !f;
        f := !e;
        e := Int64.add !d t1;
        d := !c;
        c := !b;
        b := !a;
        a := Int64.add t1 t2
      done;

      h0 := Int64.add !h0 !a;
      h1 := Int64.add !h1 !b;
      h2 := Int64.add !h2 !c;
      h3 := Int64.add !h3 !d;
      h4 := Int64.add !h4 !e;
      h5 := Int64.add !h5 !f;
      h6 := Int64.add !h6 !g;
      h7 := Int64.add !h7 !h
    done;

    let out = Bytes.create 64 in
    Bytes.set_int64_be out 0 !h0;
    Bytes.set_int64_be out 8 !h1;
    Bytes.set_int64_be out 16 !h2;
    Bytes.set_int64_be out 24 !h3;
    Bytes.set_int64_be out 32 !h4;
    Bytes.set_int64_be out 40 !h5;
    Bytes.set_int64_be out 48 !h6;
    Bytes.set_int64_be out 56 !h7;
    out
;;

let digest_string_hex (s : string) : string =
    Hex.of_bytes (digest_bytes (Bytes.of_string s))
;;

let%test "sha512 empty" =
    digest_string_hex ""
    = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
       47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
;;

let%test "sha512 abc" =
    digest_string_hex "abc"
    = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
       2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
;;

let%test "sha512 quick brown fox" =
    digest_string_hex "The quick brown fox jumps over the lazy dog"
    = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64\
       2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
;;
