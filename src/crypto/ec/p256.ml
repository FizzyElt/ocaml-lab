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

let z_of_bytes_be (b : bytes) : Z.t =
    if Bytes.length b = 0 then
      Z.zero
    else
      Z.of_string ("0x" ^ Hex.of_bytes b)
;;
let bytes_of_z_be_padded (x : Z.t) ~(len : int) : bytes =
    if Z.sign x < 0 then invalid_arg "bytes_of_z_be_padded: negative integer";

    let raw = Z.to_bits x in
    let raw_len = String.length raw in
    let out = Bytes.make len '\x00' in

    if raw_len > len then invalid_arg "bytes_of_z_be_padded: integer too large";

    for i = 0 to raw_len - 1 do
      let byte = Char.code raw.[raw_len - 1 - i] in
      Bytes.set_uint8 out (len - 1 - i) byte
    done;

    out
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

let is_on_curve (pt : point) : bool =
    match affine_of_point pt with
    | Infinity_affine -> false
    | Affine { x; y } ->
      let lhs = fe_square y in
      let x2 = fe_square x in
      let x3 = fe_mul x2 x in
      let ax = fe_mul a x in
      let rhs = fe_add (fe_add x3 ax) b in
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
