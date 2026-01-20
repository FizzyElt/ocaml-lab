let map2_bytes (opt : int -> int -> int) (a : bytes) (b : bytes) =
    let len = Bytes.length a in
    if Bytes.length b <> len then invalid_arg "length mismatch";
    let out = Bytes.create len in
    for i = 0 to len - 1 do
      let v = opt (Bytes.get_uint8 a i) (Bytes.get_uint8 b i) in
      Bytes.set_uint8 out i v
    done;
    out
;;

let xor_bytes = map2_bytes ( lxor )

let and_bytes = map2_bytes ( land )

let or_bytes = map2_bytes ( lor )

let not_bytes (a : bytes) =
    let len = Bytes.length a in
    let out = Bytes.create len in
    for i = 0 to len - 1 do
      let v = lnot (Bytes.get_uint8 a i) in
      Bytes.set_uint8 out i v
    done;
    out
;;

let equal_bytes_ct (a : bytes) (b : bytes) : bool =
    let la = Bytes.length a in
    let lb = Bytes.length b in
    let diff = ref (la lxor lb) in
    let n = min la lb in
    for i = 0 to n - 1 do
      diff := !diff lor (Bytes.get_uint8 a i lxor Bytes.get_uint8 b i)
    done;

    !diff = 0
;;
