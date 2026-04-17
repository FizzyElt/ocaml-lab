let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

let inv_alphabet_table =
    begin
      let table = Array.make 256 (-1) in
      for i = 0 to String.length alphabet - 1 do
        table.(Char.code alphabet.[i]) <- i;
        (* case-insensitive on decode *)
        let c = alphabet.[i] in
        if c >= 'A' && c <= 'Z' then
          table.(Char.code (Char.lowercase_ascii c)) <- i
      done;
      table
    end
;;

let encode (data : bytes) : string =
    let len = Bytes.length data in
    let out_len = (len + 4) / 5 * 8 in
    let out = Bytes.create out_len in

    let get i =
        if i < len then
          Some (Bytes.get_uint8 data i)
        else
          None
    in
    let v = function
        | Some x -> x
        | None -> 0
    in

    let rec loop i o =
        if i >= len then
          ()
        else (
          (* Load up to 5 bytes for this 40-bit block. *)
          let b0 = Bytes.get_uint8 data i in
          let b1 = get (i + 1) in
          let b2 = get (i + 2) in
          let b3 = get (i + 3) in
          let b4 = get (i + 4) in

          (* Split into 8 Base32 indices (5-bit chunks). *)
          let i0 = b0 lsr 3 in
          let i1 = ((b0 land 0x07) lsl 2) lor (v b1 lsr 6) in
          let i2 = (v b1 lsr 1) land 0x1F in
          let i3 = ((v b1 land 0x01) lsl 4) lor (v b2 lsr 4) in
          let i4 = ((v b2 land 0x0F) lsl 1) lor (v b3 lsr 7) in
          let i5 = (v b3 lsr 2) land 0x1F in
          let i6 = ((v b3 land 0x03) lsl 3) lor (v b4 lsr 5) in
          let i7 = v b4 land 0x1F in

          Bytes.set out o alphabet.[i0];
          Bytes.set out (o + 1) alphabet.[i1];
          ( match b1 with
            | Some _ -> Bytes.set out (o + 2) alphabet.[i2]
            | None -> Bytes.set out (o + 2) '=' );
          ( match b1 with
            | Some _ -> Bytes.set out (o + 3) alphabet.[i3]
            | None -> Bytes.set out (o + 3) '=' );
          ( match b2 with
            | Some _ -> Bytes.set out (o + 4) alphabet.[i4]
            | None -> Bytes.set out (o + 4) '=' );
          ( match b3 with
            | Some _ -> Bytes.set out (o + 5) alphabet.[i5]
            | None -> Bytes.set out (o + 5) '=' );
          ( match b3 with
            | Some _ -> Bytes.set out (o + 6) alphabet.[i6]
            | None -> Bytes.set out (o + 6) '=' );
          ( match b4 with
            | Some _ -> Bytes.set out (o + 7) alphabet.[i7]
            | None -> Bytes.set out (o + 7) '=' );
          loop (i + 5) (o + 8)
        )
    in
    loop 0 0;
    Bytes.to_string out
;;

let encode_unpadded (data : bytes) : string =
    let s = encode data in
    let len = String.length s in
    let rec trim i =
        if i > 0 && s.[i - 1] = '=' then
          trim (i - 1)
        else
          i
    in
    String.sub s 0 (trim len)
;;

(* Decode a well-formed, padded Base32 string (length % 8 = 0). *)
let decode_padded (s : string) : bytes =
    let len = String.length s in
    if len mod 8 <> 0 then invalid_arg "base32: invalid length";

    let pad =
        let rec count i acc =
            if i < 0 || s.[i] <> '=' then
              acc
            else
              count (i - 1) (acc + 1)
        in
        if len = 0 then
          0
        else
          count (len - 1) 0
    in
    let bytes_in_last =
        match pad with
        | 0 -> 5
        | 1 -> 4
        | 3 -> 3
        | 4 -> 2
        | 6 -> 1
        | _ -> invalid_arg "base32: invalid padding"
    in
    let blocks = len / 8 in
    let out_len =
        if blocks = 0 then
          0
        else
          ((blocks - 1) * 5) + bytes_in_last
    in
    let out = Bytes.create out_len in

    let idx c =
        let v = inv_alphabet_table.(Char.code c) in
        if v < 0 then invalid_arg "base32: invalid character";
        v
    in
    (* Enforce canonical RFC 4648 encoding by checking discarded bits are zero. *)
    let require_zero_bits value mask =
        if value land mask <> 0 then invalid_arg "base32: non-canonical padding bits"
    in

    let rec loop i o =
        if i >= len then
          ()
        else (
          let last = i + 8 = len in
          let block_pad =
              if last then
                pad
              else
                0
          in
          let n0 = idx s.[i] in
          let n1 = idx s.[i + 1] in
          let b0 = (n0 lsl 3) lor (n1 lsr 2) in
          Bytes.set_uint8 out o b0;
          if block_pad = 6 then require_zero_bits n1 0x03;

          if block_pad <= 4 then (
            let n2 = idx s.[i + 2] in
            let n3 = idx s.[i + 3] in
            let b1 =
                ((n1 land 0x03) lsl 6) lor (n2 lsl 1) lor (n3 lsr 4)
            in
            Bytes.set_uint8 out (o + 1) b1;
            if block_pad = 4 then require_zero_bits n3 0x0F;

            if block_pad <= 3 then (
              let n4 = idx s.[i + 4] in
              let b2 = ((n3 land 0x0F) lsl 4) lor (n4 lsr 1) in
              Bytes.set_uint8 out (o + 2) b2;
              if block_pad = 3 then require_zero_bits n4 0x01;

              if block_pad <= 1 then (
                let n5 = idx s.[i + 5] in
                let n6 = idx s.[i + 6] in
                let b3 =
                    ((n4 land 0x01) lsl 7)
                    lor (n5 lsl 2)
                    lor (n6 lsr 3)
                in
                Bytes.set_uint8 out (o + 3) b3;
                if block_pad = 1 then require_zero_bits n6 0x07;

                if block_pad = 0 then (
                  let n7 = idx s.[i + 7] in
                  let b4 = ((n6 land 0x07) lsl 5) lor n7 in
                  Bytes.set_uint8 out (o + 4) b4
                )
              )
            )
          );
          loop (i + 8) (o + 5)
        )
    in
    loop 0 0;
    out
;;

let decode (s : string) : bytes =
    decode_padded s
;;

let decode_unpadded (s : string) : bytes =
    (* Strip any trailing '=' the caller may have included, then re-pad. *)
    let len = String.length s in
    let rec trim i =
        if i > 0 && s.[i - 1] = '=' then
          trim (i - 1)
        else
          i
    in
    let data_len = trim len in
    let pad =
        match data_len mod 8 with
        | 0 -> 0
        | 2 -> 6
        | 4 -> 4
        | 5 -> 3
        | 7 -> 1
        | _ -> invalid_arg "base32: invalid length"
    in
    let padded = Bytes.create (data_len + pad) in
    Bytes.blit_string s 0 padded 0 data_len;
    for i = data_len to data_len + pad - 1 do
      Bytes.set padded i '='
    done;
    decode_padded (Bytes.unsafe_to_string padded)
;;

(* RFC 4648 test vectors. *)
let%test _ = encode (Bytes.of_string "") = ""
let%test _ = encode (Bytes.of_string "f") = "MY======"
let%test _ = encode (Bytes.of_string "fo") = "MZXQ===="
let%test _ = encode (Bytes.of_string "foo") = "MZXW6==="
let%test _ = encode (Bytes.of_string "foob") = "MZXW6YQ="
let%test _ = encode (Bytes.of_string "fooba") = "MZXW6YTB"
let%test _ = encode (Bytes.of_string "foobar") = "MZXW6YTBOI======"

let%test _ = encode_unpadded (Bytes.of_string "") = ""
let%test _ = encode_unpadded (Bytes.of_string "f") = "MY"
let%test _ = encode_unpadded (Bytes.of_string "fo") = "MZXQ"
let%test _ = encode_unpadded (Bytes.of_string "foo") = "MZXW6"
let%test _ = encode_unpadded (Bytes.of_string "foob") = "MZXW6YQ"
let%test _ = encode_unpadded (Bytes.of_string "fooba") = "MZXW6YTB"
let%test _ = encode_unpadded (Bytes.of_string "foobar") = "MZXW6YTBOI"

let%test _ = Bytes.equal (decode "") (Bytes.of_string "")
let%test _ = Bytes.equal (decode "MY======") (Bytes.of_string "f")
let%test _ = Bytes.equal (decode "MZXQ====") (Bytes.of_string "fo")
let%test _ = Bytes.equal (decode "MZXW6===") (Bytes.of_string "foo")
let%test _ = Bytes.equal (decode "MZXW6YQ=") (Bytes.of_string "foob")
let%test _ = Bytes.equal (decode "MZXW6YTB") (Bytes.of_string "fooba")
let%test _ = Bytes.equal (decode "MZXW6YTBOI======") (Bytes.of_string "foobar")

(* Case-insensitive. *)
let%test _ = Bytes.equal (decode "mzxw6ytboi======") (Bytes.of_string "foobar")

let%test _ = Bytes.equal (decode_unpadded "") (Bytes.of_string "")
let%test _ = Bytes.equal (decode_unpadded "MY") (Bytes.of_string "f")
let%test _ = Bytes.equal (decode_unpadded "MZXQ") (Bytes.of_string "fo")
let%test _ = Bytes.equal (decode_unpadded "MZXW6") (Bytes.of_string "foo")
let%test _ = Bytes.equal (decode_unpadded "MZXW6YQ") (Bytes.of_string "foob")
let%test _ = Bytes.equal (decode_unpadded "MZXW6YTB") (Bytes.of_string "fooba")
let%test _ = Bytes.equal (decode_unpadded "MZXW6YTBOI") (Bytes.of_string "foobar")

(* Tolerates extra padding too. *)
let%test _ = Bytes.equal (decode_unpadded "MY======") (Bytes.of_string "f")

(* Google Authenticator style secret. *)
let%test _ =
    Bytes.equal
      (decode_unpadded "JBSWY3DPEHPK3PXP")
      (Bytes.of_string "Hello!\xde\xad\xbe\xef")
;;

(* Reject non-canonical encodings with non-zero discarded bits. *)
let%test _ =
    try
      let _ = decode "MZ======" in
      false
    with
    | Invalid_argument _ -> true
;;
