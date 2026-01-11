open Encrypt
open Decrypt
open Variant
open Core
open Key_schedule

let encrypt ~(variant : variant) ~(key : bytes) ~(iv : bytes) (pt : bytes) =
    let padded = pkcs7_pad pt in

    let keys = key_expansion ~variant key in
    let prev = ref iv in

    let out = Bytes.copy padded in

    let block = Bytes.create 16 in
    for i = 0 to (Bytes.length padded / 16) - 1 do
      Bytes.blit padded (i * 16) block 0 16;
      let x = xor_bytes block !prev in
      let c = encrypt_block_with_keys ~variant x keys in

      Bytes.blit c 0 out (i * 16) 16;
      prev := c
    done;
    out
;;

let decrypt ~(variant : variant) ~(key : bytes) ~(iv : bytes) (ct : bytes) =
    if Bytes.length ct mod 16 <> 0 then invalid_arg "decrypt_cbc: length";

    let keys = key_expansion ~variant key in
    let prev = ref iv in
    let out = Bytes.create (Bytes.length ct) in
    let block = Bytes.create 16 in
    for i = 0 to (Bytes.length ct / 16) - 1 do
      Bytes.blit ct (i * 16) block 0 16;
      let p = decrypt_block_with_keys ~variant block keys |> xor_bytes !prev in
      Bytes.blit p 0 out (i * 16) 16;
      prev := Bytes.copy block
    done;

    pkcs7_unpad out
;;

open Codec
let%test "cbc encrypt: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    let ct = encrypt ~variant:Aes_128 ~key ~iv pt in
    (* ignore last 16 bytes *)
    let ct_prefix = Bytes.sub ct 0 64 in

    let exp =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    in

    exp = ct_prefix
;;

let%test "cbc encrypt: pt.length mod 16 <> 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in
    let ct = encrypt ~variant:Aes_128 ~key ~iv pt in

    let exp =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295162c509bd396148c7ce205978abae9ee61"
    in

    exp = ct
;;

let%test "cbc encrypt aes192: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    let ct = encrypt ~variant:Aes_192 ~key ~iv pt in
    (* ignore last 16 bytes *)
    let ct_prefix = Bytes.sub ct 0 64 in

    let exp =
        Hex.to_bytes
          "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"
    in

    exp = ct_prefix
;;

let%test "cbc encrypt aes256: pt.length mod 16 = 0" =
    let key =
        Hex.to_bytes
          "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    let ct = encrypt ~variant:Aes_256 ~key ~iv pt in
    (* ignore last 16 bytes *)
    let ct_prefix = Bytes.sub ct 0 64 in

    let exp =
        Hex.to_bytes
          "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
    in

    exp = ct_prefix
;;

let%test "cbc decrypt: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012"
    in
    let dt = decrypt ~variant:Aes_128 ~key ~iv ct in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    pt = dt
;;

let%test "cbc decrypt: pt.length mod 16 <> 0" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295162c509bd396148c7ce205978abae9ee61"
    in
    let dt = decrypt ~variant:Aes_128 ~key ~iv ct in

    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in

    pt = dt
;;

let%test "cbc decrypt aes192: pt.length mod 16 = 0" =
    let key = Hex.to_bytes "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd612ccd79224b350935d45dd6a98f8176"
    in
    let dt = decrypt ~variant:Aes_192 ~key ~iv ct in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    pt = dt
;;

let%test "cbc decrypt aes256: pt.length mod 16 = 0" =
    let key =
        Hex.to_bytes
          "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let ct =
        Hex.to_bytes
          "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644"
    in
    let dt = decrypt ~variant:Aes_256 ~key ~iv ct in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    in
    pt = dt
;;

let%test "cbc encrypt and decrypt" =
    let key = Hex.to_bytes "2b7e151628aed2a6abf7158809cf4f3c" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in

    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in

    let ct = encrypt ~variant:Aes_128 ~key ~iv pt in

    pt = decrypt ~variant:Aes_128 ~key ~iv ct
;;

let%test "cbc encrypt and decrypt aes192" =
    let key = Hex.to_bytes "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in

    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in

    let ct = encrypt ~variant:Aes_192 ~key ~iv pt in

    pt = decrypt ~variant:Aes_192 ~key ~iv ct
;;

let%test "cbc encrypt and decrypt aes256" =
    let key =
        Hex.to_bytes
          "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    in
    let iv = Hex.to_bytes "000102030405060708090a0b0c0d0e0f" in
    let pt =
        Hex.to_bytes
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b"
    in

    let ct = encrypt ~variant:Aes_256 ~key ~iv pt in

    pt = decrypt ~variant:Aes_256 ~key ~iv ct
;;
