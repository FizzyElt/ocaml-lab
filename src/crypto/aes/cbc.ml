open Encrypt
open Decrypt
open Variant

let _encrypt ~(variant : variant) ~(key : bytes) ~(iv : bytes) (pt : bytes) =
    encrypt_cbc ~variant pt key iv
;;
let _decrypt ~(variant : variant) ~(key : bytes) ~(iv : bytes) (ct : bytes) =
    decrypt_cbc ~variant ct key iv
;;
