open Table

let xor_bytes (a : bytes) (b : bytes) : bytes =
    let len = Bytes.length a in
    if Bytes.length b <> len then invalid_arg "xor_bytes: length mismatch";
    let out = Bytes.create len in
    for i = 0 to len - 1 do
      let v = Bytes.get_uint8 a i lxor Bytes.get_uint8 b i in
      Bytes.set_uint8 out i v
    done;
    out
;;

let sub_bytes (state : bytes) : bytes =
    let result = Bytes.copy state in
    for i = 0 to 15 do
      let byte = Bytes.get_uint8 state i in
      Bytes.set_uint8 result i sbox.(byte)
    done;

    result
;;

let inv_sub_bytes (state : bytes) : bytes =
    let result = Bytes.copy state in
    for i = 0 to 15 do
      let byte = Bytes.get_uint8 state i in
      Bytes.set_uint8 result i inv_sbox.(byte)
    done;
    result
;;

let shift_rows (state : bytes) : bytes =
    let result = Bytes.create 16 in

    (* Row 0 *)
    Bytes.set result 0 (Bytes.get state 0);
    Bytes.set result 4 (Bytes.get state 4);
    Bytes.set result 8 (Bytes.get state 8);
    Bytes.set result 12 (Bytes.get state 12);

    (* Row 1: <- 1 *)
    Bytes.set result 1 (Bytes.get state 5);
    Bytes.set result 5 (Bytes.get state 9);
    Bytes.set result 9 (Bytes.get state 13);
    Bytes.set result 13 (Bytes.get state 1);

    (* Row 2: <- 2 *)
    Bytes.set result 2 (Bytes.get state 10);
    Bytes.set result 6 (Bytes.get state 14);
    Bytes.set result 10 (Bytes.get state 2);
    Bytes.set result 14 (Bytes.get state 6);

    (* Row 3: <- 3 *)
    Bytes.set result 3 (Bytes.get state 15);
    Bytes.set result 7 (Bytes.get state 3);
    Bytes.set result 11 (Bytes.get state 7);
    Bytes.set result 15 (Bytes.get state 11);

    result
;;

let inv_shift_rows (state : bytes) : bytes =
    let result = Bytes.copy state in

    (* Row 0 *)
    Bytes.set result 0 (Bytes.get state 0);
    Bytes.set result 4 (Bytes.get state 4);
    Bytes.set result 8 (Bytes.get state 8);
    Bytes.set result 12 (Bytes.get state 12);

    (* Row 1: -> 1 *)
    Bytes.set result 1 (Bytes.get state 13);
    Bytes.set result 5 (Bytes.get state 1);
    Bytes.set result 9 (Bytes.get state 5);
    Bytes.set result 13 (Bytes.get state 9);

    (* Row 2: -> 2 *)
    Bytes.set result 2 (Bytes.get state 10);
    Bytes.set result 6 (Bytes.get state 14);
    Bytes.set result 10 (Bytes.get state 2);
    Bytes.set result 14 (Bytes.get state 6);

    (* Row 3: -> 3 *)
    Bytes.set result 3 (Bytes.get state 7);
    Bytes.set result 7 (Bytes.get state 11);
    Bytes.set result 11 (Bytes.get state 15);
    Bytes.set result 15 (Bytes.get state 3);

    result
;;

let xtime (x : int) : int =
    let x = x land 0xff in
    let shifted = (x lsl 1) land 0xff in
    if x land 0x80 <> 0 then
      shifted lxor 0x1b
    else
      shifted
;;

let mul2 (x : int) : int = xtime x

let mul3 (x : int) : int = mul2 x lxor x

let mul9 (x : int) : int =
    let x8 = x |> xtime |> xtime |> xtime in
    x8 lxor x
;;

let mul11 (x : int) : int =
    let x2 = xtime x in
    let x8 = x2 |> xtime |> xtime in

    x8 lxor x2 lxor x
;;

let mul13 (x : int) : int =
    let x4 = x |> xtime |> xtime in
    let x8 = xtime x4 in

    x8 lxor x4 lxor x
;;

let mul14 (x : int) : int =
    let x2 = xtime x in
    let x4 = xtime x2 in
    let x8 = xtime x4 in

    x8 lxor x4 lxor x2
;;

let mix_column (a0 : int) (a1 : int) (a2 : int) (a3 : int)
  : int * int * int * int
  =
    (* 2 3 1 1  a0 *)
    (* 1 2 3 1  a1 *)
    (* 1 1 2 3  a2 *)
    (* 3 1 1 2  a3 *)
    let b0 = mul2 a0 lxor mul3 a1 lxor a2 lxor a3 in
    let b1 = a0 lxor mul2 a1 lxor mul3 a2 lxor a3 in
    let b2 = a0 lxor a1 lxor mul2 a2 lxor mul3 a3 in
    let b3 = mul3 a0 lxor a1 lxor a2 lxor mul2 a3 in
    (b0, b1, b2, b3)
;;

let inv_mix_column (a0 : int) (a1 : int) (a2 : int) (a3 : int)
  : int * int * int * int
  =
    (* E B D 9  a0 *)
    (* 9 E B D  a1 *)
    (* D 9 E B  a2 *)
    (* B D 9 E  a3 *)
    let b0 = mul14 a0 lxor mul11 a1 lxor mul13 a2 lxor mul9 a3 in
    let b1 = mul9 a0 lxor mul14 a1 lxor mul11 a2 lxor mul13 a3 in
    let b2 = mul13 a0 lxor mul9 a1 lxor mul14 a2 lxor mul11 a3 in
    let b3 = mul11 a0 lxor mul13 a1 lxor mul9 a2 lxor mul14 a3 in

    (b0, b1, b2, b3)
;;

let mix_columns (state : bytes) : bytes =
    let result = Bytes.copy state in
    for c = 0 to 3 do
      let i = c * 4 in
      let a0 = Bytes.get_uint8 state (i + 0) in
      let a1 = Bytes.get_uint8 state (i + 1) in
      let a2 = Bytes.get_uint8 state (i + 2) in
      let a3 = Bytes.get_uint8 state (i + 3) in

      let (b0, b1, b2, b3) = mix_column a0 a1 a2 a3 in

      Bytes.set_uint8 result (i + 0) b0;
      Bytes.set_uint8 result (i + 1) b1;
      Bytes.set_uint8 result (i + 2) b2;
      Bytes.set_uint8 result (i + 3) b3
    done;
    result
;;

let inv_mix_columns (state : bytes) : bytes =
    let result = Bytes.copy state in
    for c = 0 to 3 do
      let i = c * 4 in
      let a0 = Bytes.get_uint8 state (i + 0) in
      let a1 = Bytes.get_uint8 state (i + 1) in
      let a2 = Bytes.get_uint8 state (i + 2) in
      let a3 = Bytes.get_uint8 state (i + 3) in

      let (b0, b1, b2, b3) = inv_mix_column a0 a1 a2 a3 in

      Bytes.set_uint8 result (i + 0) b0;
      Bytes.set_uint8 result (i + 1) b1;
      Bytes.set_uint8 result (i + 2) b2;
      Bytes.set_uint8 result (i + 3) b3
    done;
    result
;;

let add_round_key (state : bytes) ~(round_key : bytes) : bytes =
    let result = Bytes.copy state in
    for i = 0 to 15 do
      let s = Bytes.get_uint8 state i in
      let k = Bytes.get_uint8 round_key i in
      Bytes.set_uint8 result i (s lxor k)
    done;
    result
;;
