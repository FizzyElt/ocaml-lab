open Codec

type fe = Z.t

type scalar = Z.t

type point =
  | Infinity
  | Point of
      { x : bytes;
        y : bytes
      }

type affine =
  | Infinity_affine
  | Affine of
      { x : Z.t;
        y : Z.t
      }

let coordinate_size_bytes = 32
let scalar_size_bytes = 32

let p =
    Z.of_string
      "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
;;
let a =
    Z.of_string
      "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
;;
let b =
    Z.of_string
      "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
;;
let gx =
    Z.of_string
      "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
;;
let gy =
    Z.of_string
      "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
;;
let n =
    Z.of_string
      "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
;;

let mod_p (x : Z.t) : Z.t =
    let r = Z.erem x p in
    if Z.sign r < 0 then
      Z.add r p
    else
      r
;;

let fe_add a b = mod_p Z.(a + b)
let fe_sub a b = mod_p Z.(a - b)
let fe_mul a b = mod_p Z.(a * b)
let fe_square a = mod_p Z.(a * a)

let ( %+ ) = fe_add
let ( %- ) = fe_sub
let ( %* ) = fe_mul

let z_of_bytes_be (b : bytes) : Z.t =
    if Bytes.length b = 0 then
      Z.zero
    else
      Z.of_string ("0x" ^ Hex.of_bytes b)
;;
let bytes_of_z_be_padded (x : Z.t) ~(len : int) : bytes =
    if Z.sign x < 0 then invalid_arg "bytes_of_z_be_padded: negative integer";

    let hex = Z.format "%x" x in
    let hex =
        if String.length hex mod 2 = 1 then
          "0" ^ hex
        else
          hex
    in

    let byte_len = String.length hex / 2 in
    if byte_len > len then invalid_arg "bytes_of_z_be_padded: integer too large";

    let padded_hex = String.make ((len - byte_len) * 2) '0' ^ hex in
    Hex.to_bytes padded_hex
;;

let scalar_of_bytes (b : bytes) : Z.t =
    if Bytes.length b <> scalar_size_bytes then
      invalid_arg "scalar_of_bytes: invalid length";

    let d = z_of_bytes_be b in
    if Z.compare d Z.one < 0 || Z.compare d n >= 0 then
      invalid_arg "scalar_of_bytes: out of range";

    d
;;
let scalar_to_bytes (z : Z.t) : bytes =
    if Z.compare z Z.one < 0 || Z.compare z n >= 0 then
      invalid_arg "scalar_of_bytes: out of range";
    bytes_of_z_be_padded z ~len:scalar_size_bytes
;;

let affine_of_point (pt : point) : affine =
    match pt with
    | Infinity -> Infinity_affine
    | Point { x; y } -> Affine { x = z_of_bytes_be x; y = z_of_bytes_be y }
;;

let point_of_affine (pt : affine) : point =
    match pt with
    | Infinity_affine -> Infinity
    | Affine { x; y } ->
      Point
        { x = bytes_of_z_be_padded x ~len:coordinate_size_bytes;
          y = bytes_of_z_be_padded y ~len:coordinate_size_bytes
        }
;;

let is_on_curve (pt : point) : bool =
    match affine_of_point pt with
    | Infinity_affine -> false
    | Affine { x; y } ->
      let lhs = fe_square y in
      let x2 = fe_square x in
      let x3 = x2 %* x in
      let ax = a %* x in
      let rhs = x3 %+ ax %+ b in
      Z.equal lhs rhs
;;

let point_of_uncompressed_bytes (b : bytes) : point =
    if Bytes.length b <> 65 then
      invalid_arg "point_of_uncompressed_bytes: invalid length";

    if Bytes.get_int8 b 0 <> 0x04 then
      invalid_arg "point_of_uncompressed_bytes: expected uncompressed point";

    let x = Bytes.sub b 1 coordinate_size_bytes in
    let y = Bytes.sub b (1 + coordinate_size_bytes) coordinate_size_bytes in

    Point { x; y }
;;

let point_to_uncompressed_bytes (pt : point) : bytes =
    match pt with
    | Infinity -> invalid_arg "point_to_uncompressed_bytes: infinity"
    | Point { x; y } ->
      if Bytes.length x <> coordinate_size_bytes then
        invalid_arg "point_to_uncompressed_bytes: invalid x length";
      if Bytes.length y <> coordinate_size_bytes then
        invalid_arg "point_to_uncompressed_bytes: invalid y length";

      let out = Bytes.create (1 + (2 * coordinate_size_bytes)) in
      Bytes.set_uint8 out 0 0x04;
      Bytes.blit x 0 out 1 coordinate_size_bytes;
      Bytes.blit y 0 out (1 + coordinate_size_bytes) coordinate_size_bytes;

      out
;;

let is_valid_public_key (pt : point) : bool =
    match affine_of_point pt with
    | Infinity_affine -> false
    | Affine { x; y } ->
      Z.compare x Z.zero >= 0
      && Z.compare x p < 0
      && Z.compare y Z.zero >= 0
      && Z.compare y p < 0
      && is_on_curve pt
;;

let fe_inv (x : Z.t) : Z.t = Z.invert x p

let point_double (pt : affine) : affine =
    match pt with
    | Infinity_affine -> Infinity_affine
    | Affine { x; y } ->
      if Z.equal y Z.zero then
        Infinity_affine
      else begin
        let three_x2 = Z.of_int 3 %* fe_square x in
        let numerator = three_x2 %+ a in
        let denominator = Z.of_int 2 %* y in
        (* lambda = (3*x^2 + a) / (2*y) mod p *)
        let lambda = numerator %* fe_inv denominator in
        (* x3 = lambda^2 - 2*x mod p *)
        let x3 = fe_square lambda %- (Z.of_int 2 %* x) in
        (* y3 = lambda*(x - x3) - y mod p *)
        let y3 = lambda %* (x %- x3) %- y in
        Affine { x = x3; y = y3 }
      end
;;

let point_add (p1 : affine) (p2 : affine) : affine =
    match (p1, p2) with
    | (Infinity_affine, q) -> q
    | (p, Infinity_affine) -> p
    | (Affine { x = x1; y = y1 }, Affine { x = x2; y = y2 }) ->
      if Z.equal x1 x2 then
        if Z.equal y1 y2 then
          point_double p1
        else
          Infinity_affine
      else begin
        let numerator = y2 %- y1 in
        let denominator = x2 %- x1 in
        (* lambda = (y2 - y1) / (x2 - x1) mod p *)
        let lambda = numerator %* fe_inv denominator in
        (* x3 = lambda^2 - x1 - x2 mod p *)
        let x3 = fe_square lambda %- x1 %- x2 in
        (* y3 = lambda*(x1 - x3) - y1 mod p *)
        let y3 = lambda %* (x1 %- x3) %- y1 in
        Affine { x = x3; y = y3 }
      end
;;

let g_affine = Affine { x = gx; y = gy }
let g_point = point_of_affine g_affine

let scalar_mult (k : Z.t) (p : point) : point =
    if Z.sign k < 0 then invalid_arg "scalar_mult: negative scalar";

    match affine_of_point p with
    | Infinity_affine -> Infinity
    | base ->
      let rec loop acc cur i =
          if i >= Z.numbits k then
            acc
          else (
            let acc =
                if Z.testbit k i then
                  point_add acc cur
                else
                  acc
            in
            let cur = point_double cur in
            loop acc cur (i + 1)
          )
      in
      point_of_affine (loop Infinity_affine base 0)
;;

let scalar_mult_base (k : Z.t) : point = scalar_mult k g_point

(* test *)

let%test "fe_inv" =
    let x = Z.of_int 7 in
    let inv = fe_inv x in
    Z.equal (x %* inv) Z.one
;;

let%test "fe_inv gx" =
    let inv = fe_inv gx in
    Z.equal (gx %* inv) Z.one
;;

let%test "generator is on curve" = is_on_curve g_point

let%test "point_double keeps point on curve" =
    match point_of_affine (point_double g_affine) with
    | Infinity -> false
    | pt -> is_on_curve pt
;;

let%test "point_add p p equals point_double p" =
    let lhs = point_add g_affine g_affine in
    let rhs = point_double g_affine in
    match (point_of_affine lhs, point_of_affine rhs) with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "point_add infinity left identity" =
    match (point_of_affine (point_add Infinity_affine g_affine), g_point) with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "point_add infinity right identity" =
    match (point_of_affine (point_add g_affine Infinity_affine), g_point) with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "point_add inverse gives infinity" =
    let neg_g = Affine { x = gx; y = mod_p Z.(-gy) } in
    match point_add g_affine neg_g with
    | Infinity_affine -> true
    | Affine _ -> false
;;

let%test "scalar_mult 0 = infinity" =
    match scalar_mult Z.zero g_point with
    | Infinity -> true
    | Point _ -> false
;;

let%test "scalar_mult 1 g = g" =
    match (scalar_mult Z.one g_point, g_point) with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "scalar_mult 2 g = point_double g" =
    match
      (scalar_mult (Z.of_int 2) g_point, point_of_affine (point_double g_affine))
    with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "scalar_mult_base 1 = g" =
    match (scalar_mult_base Z.one, g_point) with
    | (Point { x = x1; y = y1 }, Point { x = x2; y = y2 }) ->
      Bytes.equal x1 x2 && Bytes.equal y1 y2
    | _ -> false
;;

let%test "scalar_mult_base n = infinity" =
    match scalar_mult_base n with
    | Infinity -> true
    | Point _ -> false
;;
