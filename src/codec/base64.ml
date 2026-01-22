let alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
;;

let inv_alphabet_table =
    begin
      let table = Array.make 256 (-1) in
      for i = 0 to String.length alphabet - 1 do
        table.(Char.code alphabet.[i]) <- i
      done;
      table
    end
;;

let encode (data : bytes) =
    let len = Bytes.length data in
    let out_len = (len + 2) / 3 * 4 in

    let out = Bytes.create out_len in

    let rec loop i o =
        if i >= len then
          ()
        else (
          (* Load up to 3 bytes for this 24-bit block. *)
          let b0 = Bytes.get_uint8 data i in
          let b1 =
              if i + 1 < len then
                Some (Bytes.get_uint8 data (i + 1))
              else
                None
          in
          let b2 =
              if i + 2 < len then
                Some (Bytes.get_uint8 data (i + 2))
              else
                None
          in

          (* Split into 4 Base64 indices (6-bit chunks). *)
          let i0 = b0 lsr 2 in
          let i1 =
              ((b0 land 0x03) lsl 4)
              lor
              match b1 with
              | Some v -> v lsr 4
              | None -> 0
          in
          let i2 =
              ( match b1 with
                | Some v -> (v land 0x0F) lsl 2
                | None -> 0 )
              lor
              match b2 with
              | Some v -> v lsr 6
              | None -> 0
          in
          let i3 =
              match b2 with
              | Some v -> v land 0x3F
              | None -> 0
          in

          Bytes.set out o alphabet.[i0];
          Bytes.set out (o + 1) alphabet.[i1];

          ( match b1 with
            | Some _ -> Bytes.set out (o + 2) alphabet.[i2]
            | None -> Bytes.set out (o + 2) '=' );
          ( match b2 with
            | Some _ -> Bytes.set out (o + 3) alphabet.[i3]
            | None -> Bytes.set out (o + 3) '=' );
          loop (i + 3) (o + 4)
        )
    in
    loop 0 0;
    Bytes.to_string out
;;

let encode_url (data : bytes) =
    let s = encode data in
    let len = String.length s in
    let rec trim i =
        if i > 0 && s.[i - 1] = '=' then
          trim (i - 1)
        else
          i
    in
    let out_len = trim len in
    let out = Bytes.create out_len in
    for i = 0 to out_len - 1 do
      let c = s.[i] in
      let c' =
          match c with
          | '+' -> '-'
          | '/' -> '_'
          | _ -> c
      in
      Bytes.set out i c'
    done;
    Bytes.to_string out
;;

let decode (s : string) =
    let len = String.length s in
    if len mod 4 <> 0 then invalid_arg "base64: invalid length";

    let pad =
        ( if len > 0 && s.[len - 1] = '=' then
            1
          else
            0 )
        +
        if len > 1 && s.[len - 2] = '=' then
          1
        else
          0
    in

    let out_len = (len / 4 * 3) - pad in
    let out = Bytes.create out_len in

    let idx c =
        let v = inv_alphabet_table.(Char.code c) in
        if v < 0 then invalid_arg "base64: invalid character";
        v
    in
    let rec loop i o =
        if i >= len then
          ()
        else (
          let c0 = s.[i] in
          let c1 = s.[i + 1] in
          let c2 = s.[i + 2] in
          let c3 = s.[i + 3] in
          ( match (c2, c3) with
            | ('=', c3) ->
              if c3 <> '=' then invalid_arg "base64: invalid padding";
              if i + 4 <> len then invalid_arg "base64: padding in middle";
              let i0 = idx c0 in
              let i1 = idx c1 in
              let b0 = (i0 lsl 2) lor (i1 lsr 4) in
              Bytes.set_uint8 out o b0
            | (c2, '=') ->
              if i + 4 <> len then invalid_arg "base64: padding in middle";
              let i0 = idx c0 in
              let i1 = idx c1 in
              let i2 = idx c2 in
              let b0 = (i0 lsl 2) lor (i1 lsr 4) in
              let b1 = ((i1 land 0x0F) lsl 4) lor (i2 lsr 2) in
              Bytes.set_uint8 out o b0;
              Bytes.set_uint8 out (o + 1) b1
            | _ ->
              let i0 = idx c0 in
              let i1 = idx c1 in
              let i2 = idx c2 in
              let i3 = idx c3 in
              let b0 = (i0 lsl 2) lor (i1 lsr 4) in
              let b1 = ((i1 land 0x0F) lsl 4) lor (i2 lsr 2) in
              let b2 = ((i2 land 0x03) lsl 6) lor i3 in
              Bytes.set_uint8 out o b0;
              Bytes.set_uint8 out (o + 1) b1;
              Bytes.set_uint8 out (o + 2) b2 );

          loop (i + 4) (o + 3)
        )
    in
    loop 0 0;
    out
;;

let decode_url (s : string) =
    let len = String.length s in
    let pad =
        match len mod 4 with
        | 0 -> 0
        | 2 -> 2
        | 3 -> 1
        | _ -> invalid_arg "base64url: invalid length"
    in
    let padded = Bytes.create (len + pad) in
    for i = 0 to len - 1 do
      let c = s.[i] in
      let c' =
          match c with
          | '-' -> '+'
          | '_' -> '/'
          | _ -> c
      in
      Bytes.set padded i c'
    done;
    for i = len to len + pad - 1 do
      Bytes.set padded i '='
    done;
    decode (Bytes.to_string padded)
;;

let%test _ = encode (Bytes.of_string "") = ""
let%test _ = encode (Bytes.of_string "f") = "Zg=="
let%test _ = encode (Bytes.of_string "fo") = "Zm8="
let%test _ = encode (Bytes.of_string "foo") = "Zm9v"
let%test _ = encode (Bytes.of_string "foobar") = "Zm9vYmFy"

let%test _ = encode_url (Bytes.of_string "") = ""
let%test _ = encode_url (Bytes.of_string "f") = "Zg"
let%test _ = encode_url (Bytes.of_string "fo") = "Zm8"
let%test _ = encode_url (Bytes.of_string "foo") = "Zm9v"
let%test _ = encode_url (Bytes.of_string "foobar") = "Zm9vYmFy"

let%test _ = Bytes.equal (decode "") (Bytes.of_string "")
let%test _ = Bytes.equal (decode "Zg==") (Bytes.of_string "f")
let%test _ = Bytes.equal (decode "Zm8=") (Bytes.of_string "fo")
let%test _ = Bytes.equal (decode "Zm9v") (Bytes.of_string "foo")
let%test _ = Bytes.equal (decode "Zm9vYmFy") (Bytes.of_string "foobar")

let%test _ = Bytes.equal (decode_url "") (Bytes.of_string "")
let%test _ = Bytes.equal (decode_url "Zg") (Bytes.of_string "f")
let%test _ = Bytes.equal (decode_url "Zm8") (Bytes.of_string "fo")
let%test _ = Bytes.equal (decode_url "Zm9v") (Bytes.of_string "foo")
let%test _ = Bytes.equal (decode_url "Zm9vYmFy") (Bytes.of_string "foobar")
