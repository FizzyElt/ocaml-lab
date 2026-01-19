open Encrypt
open Variant
open Key_schedule
open Util.Bytes_util

(* ref: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf *)

let xor_prefix ~(dst : bytes) ~(dst_offset : int) (a : bytes) (b : bytes) ~len =
    for i = 0 to len - 1 do
      let v = Bytes.get_uint8 a i lxor Bytes.get_uint8 b i in
      Bytes.set_uint8 dst (dst_offset + i) v
    done
;;

let block_of_bytes (data : bytes) (offset : int) : bytes =
    let block = Bytes.create 16 in
    let avail = Bytes.length data - offset in
    let len = min avail 16 in

    if len > 0 then Bytes.blit data offset block 0 len;
    block
;;

let write_u64_be (buf : bytes) (off : int) (v : int64) =
    for i = 0 to 7 do
      let shift = 56 - (8 * i) in
      let byte =
          Int64.(shift_right_logical v shift |> logand 0xffL |> to_int)
      in
      Bytes.set_uint8 buf (off + i) byte
    done
;;

let get_bit (b : bytes) (i : int) : int =
    let byte = Bytes.get_uint8 b (i / 8) in
    let shift = 7 - (i mod 8) in
    (byte lsr shift) land 1
;;

let shift_right_one (b : bytes) : bytes =
    let out = Bytes.create 16 in
    let carry = ref 0 in
    for i = 0 to 15 do
      let byte = Bytes.get_uint8 b i in
      let new_carry = byte land 1 in
      let shifted = (byte lsr 1) lor (!carry lsl 7) in
      Bytes.set_uint8 out i shifted;
      carry := new_carry
    done;
    out
;;

let gf_mul (x : bytes) (y : bytes) : bytes =
    let r = 0xe1 in
    let z = Bytes.create 16 in
    let v = ref (Bytes.copy y) in
    for i = 0 to 127 do
      if get_bit x i = 1 then (
        let tmp = xor_bytes z !v in
        Bytes.blit tmp 0 z 0 16
      );

      let lsb = Bytes.get_uint8 !v 15 land 1 in
      let shifted = shift_right_one !v in

      if lsb = 1 then
        Bytes.set_uint8 shifted 0 (Bytes.get_uint8 shifted 0 lxor r);

      v := shifted
    done;
    z
;;

let ghash ~(h : bytes) ~(aad : bytes) ~(ciphertext : bytes) : bytes =
    let x = ref (Bytes.create 16) in
    let update block = x := gf_mul (xor_bytes !x block) h in

    let process data =
        let len = Bytes.length data in
        let blocks = (len + 15) / 16 in
        for i = 0 to blocks - 1 do
          update (block_of_bytes data (i * 16))
        done
    in

    process aad;
    process ciphertext;

    let len_block = Bytes.create 16 in
    let aad_bits = Bytes.length aad |> Int64.of_int |> Int64.mul 8L in
    let ct_bits = Bytes.length ciphertext |> Int64.of_int |> Int64.mul 8L in
    write_u64_be len_block 0 aad_bits;
    write_u64_be len_block 8 ct_bits;

    update len_block;
    !x
;;

let inc32 (block : bytes) : bytes =
    let out = Bytes.copy block in
    let carry = ref 1 in
    for i = 15 downto 12 do
      let v = Bytes.get_uint8 out i + !carry in
      Bytes.set_uint8 out i (v land 0xff);
      carry
      := if v > 0xff then
           1
         else
           0
    done;
    out
;;

let j0_of_iv ~(h : bytes) (iv : bytes) : bytes =
    if Bytes.length iv = 12 then
      Bytes.cat iv (Bytes.of_string "\x00\x00\x00\x01")
    else
      ghash ~h ~aad:(Bytes.create 0) ~ciphertext:iv
;;

let encrypt_gctr
      ~(variant : variant)
      ~(keys : word array)
      ~(init_counter : bytes)
      (pt : bytes)
  =
    let counter = ref init_counter in
    let pt_len = Bytes.length pt in

    let ct = Bytes.create pt_len in
    let blocks = (pt_len + 15) / 16 in

    for i = 0 to blocks - 1 do
      counter := inc32 !counter;
      let ks = encrypt_block_with_keys ~variant !counter keys in

      let offset = i * 16 in
      let remain = pt_len - offset in
      let len = min remain 16 in
      let block = block_of_bytes pt offset in

      xor_prefix ~dst:ct ~dst_offset:offset block ks ~len
    done;

    ct
;;

let encrypt
      ~(variant : variant)
      ~(key : bytes)
      ~(iv : bytes)
      ~(aad : bytes)
      (pt : bytes)
  : bytes * bytes
  =
    let keys = key_expansion ~variant key in
    let h = encrypt_block_with_keys ~variant (Bytes.create 16) keys in
    let j0 = j0_of_iv ~h iv in

    let ct = encrypt_gctr ~variant ~keys ~init_counter:j0 pt in

    let s = ghash ~h ~aad ~ciphertext:ct in
    let e_j0 = encrypt_block_with_keys ~variant j0 keys in
    let tag = xor_bytes e_j0 s in

    (ct, tag)
;;

(* constant‑time equal *)
let ct_equal_tag16 (a : bytes) (b : bytes) : bool =
    let la = Bytes.length a in
    let lb = Bytes.length b in
    let buf_a = Bytes.create 16 in
    let buf_b = Bytes.create 16 in
    let len_a = min la 16 in
    let len_b = min lb 16 in

    Bytes.blit a 0 buf_a 0 len_a;
    Bytes.blit b 0 buf_b 0 len_b;

    let diff = ref (la lxor 16 lor (lb lxor 16)) in

    for i = 0 to 15 do
      diff := !diff lor (Bytes.get_uint8 buf_a i lxor Bytes.get_uint8 buf_b i)
    done;

    !diff = 0
;;

let decrypt
      ~(variant : variant)
      ~(key : bytes)
      ~(iv : bytes)
      ~(aad : bytes)
      ((ct, tag) : bytes * bytes)
  =
    let keys = key_expansion ~variant key in
    let h = encrypt_block_with_keys ~variant (Bytes.create 16) keys in

    let j0 = j0_of_iv ~h iv in

    let s = ghash ~h ~aad ~ciphertext:ct in
    let e_j0 = encrypt_block_with_keys ~variant j0 keys in
    let tag' = xor_bytes e_j0 s in

    if not (ct_equal_tag16 tag tag') then
      invalid_arg "decrypt:fail verification tag";

    let pt = encrypt_gctr ~variant ~keys ~init_counter:j0 ct in

    pt
;;

(* 
================== 
=                = 
=   test block   = 
=                = 
================== 
*)
open Codec

let%test "gcm aes128 empty pt/aad" =
    let key = Hex.to_bytes "00000000000000000000000000000000" in
    let iv = Hex.to_bytes "000000000000000000000000" in
    let pt = Hex.to_bytes "" in
    let aad = Hex.to_bytes "" in

    let (ct, tag) = encrypt ~variant:Aes_128 ~key ~iv ~aad pt in

    let exp_ct = Hex.to_bytes "" in
    let exp_tag = Hex.to_bytes "58e2fccefa7e3061367f1d57a4e7455a" in

    exp_ct = ct && exp_tag = tag
;;

let%test "gcm aes128 single block pt" =
    let key = Hex.to_bytes "00000000000000000000000000000000" in
    let iv = Hex.to_bytes "000000000000000000000000" in
    let pt = Hex.to_bytes "00000000000000000000000000000000" in
    let aad = Hex.to_bytes "" in

    let (ct, tag) = encrypt ~variant:Aes_128 ~key ~iv ~aad pt in

    let exp_ct = Hex.to_bytes "0388dace60b6a392f328c2b971b2fe78" in
    let exp_tag = Hex.to_bytes "ab6e47d42cec13bdf53a67b21257bddf" in

    exp_ct = ct && exp_tag = tag
;;

let%test "gcm aes128 with aad and multi-block pt" =
    let key = Hex.to_bytes "feffe9928665731c6d6a8f9467308308" in
    let iv = Hex.to_bytes "cafebabefacedbaddecaf888" in
    let pt =
        Hex.to_bytes
          "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    in
    let aad = Hex.to_bytes "feedfacedeadbeeffeedfacedeadbeefabaddad2" in

    let (ct, tag) = encrypt ~variant:Aes_128 ~key ~iv ~aad pt in

    let exp_ct =
        Hex.to_bytes
          "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
    in
    let exp_tag = Hex.to_bytes "5bc94fbc3221a5db94fae95ae7121a47" in

    exp_ct = ct && exp_tag = tag
;;

let%test "gcm aes128 decrypt ok" =
    let key = Hex.to_bytes "feffe9928665731c6d6a8f9467308308" in
    let iv = Hex.to_bytes "cafebabefacedbaddecaf888" in
    let pt =
        Hex.to_bytes
          "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    in
    let aad = Hex.to_bytes "feedfacedeadbeeffeedfacedeadbeefabaddad2" in
    let (ct, tag) = encrypt ~variant:Aes_128 ~key ~iv ~aad pt in
    let pt' = decrypt ~variant:Aes_128 ~key ~iv ~aad (ct, tag) in

    pt = pt'
;;

let%test "gcm aes128 decrypt fail on bad tag" =
    let key = Hex.to_bytes "00000000000000000000000000000000" in
    let iv = Hex.to_bytes "000000000000000000000000" in
    let pt = Hex.to_bytes "00000000000000000000000000000000" in
    let aad = Hex.to_bytes "" in
    let (ct, tag) = encrypt ~variant:Aes_128 ~key ~iv ~aad pt in
    let bad_tag = Bytes.copy tag in
    let first = Bytes.get_uint8 bad_tag 0 in
    Bytes.set_uint8 bad_tag 0 (first lxor 0x01);

    try
      let _ = decrypt ~variant:Aes_128 ~key ~iv ~aad (ct, bad_tag) in
      false
    with
    | Invalid_argument _ -> true
;;
