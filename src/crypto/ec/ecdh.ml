type named_curve = [ `P256 ]

type public_key =
  { curve : named_curve;
    point : P256.point
  }

type private_key =
  { curve : named_curve;
    d : P256.scalar
  }

type key_pair =
  { public_key : public_key;
    private_key : private_key
  }

(* ref https://growingswe.com/blog/elliptic-curve-cryptography *)

(* Development-only PRNG. Replace with a cryptographically secure source (CSPRNG). *)
let random_bytes (len : int) : bytes =
    let out = Bytes.create len in
    for i = 0 to len - 1 do
      Bytes.set_uint8 out i (Random.int 256)
    done;
    out
;;

let rec random_scalar () : P256.scalar =
    let raw = random_bytes P256.scalar_size_bytes in
    try P256.scalar_of_bytes raw with
    | Invalid_argument _ -> random_scalar ()
;;

let generate_key ~(named_curve : named_curve) : key_pair =
    match named_curve with
    | `P256 ->
      let d = random_scalar () in
      let point = P256.scalar_mult_base d in
      let private_key = { curve = `P256; d } in
      let public_key = { curve = `P256; point } in
      { public_key; private_key }
;;

let import_public_key_raw ~(named_curve : named_curve) (raw : bytes)
  : public_key
  =
    match named_curve with
    | `P256 ->
      let point = P256.point_of_uncompressed_bytes raw in
      if not (P256.is_valid_public_key point) then
        invalid_arg "import_public_key_raw: invalid public key";
      { curve = `P256; point }
;;

let export_public_key_raw (pub_key : public_key) : bytes =
    match pub_key.curve with
    | `P256 -> P256.point_to_uncompressed_bytes pub_key.point
;;

let import_private_key_raw ~(named_curve : named_curve) (raw : bytes)
  : private_key
  =
    match named_curve with
    | `P256 ->
      let d = P256.scalar_of_bytes raw in
      { curve = `P256; d }
;;

let export_private_key_raw (priv_key : private_key) : bytes =
    match priv_key.curve with
    | `P256 -> P256.scalar_to_bytes priv_key.d
;;

let derive_bits ~(private_key : private_key) ~(public_key : public_key) : bytes =
    match (private_key.curve, public_key.curve) with
    | (`P256, `P256) ->
      if not (P256.is_valid_public_key public_key.point) then
        invalid_arg "import_public_key_raw: invalid public key";

      let shared = P256.scalar_mult private_key.d public_key.point in
      ( match shared with
        | P256.Infinity -> invalid_arg "derive_bits: invalid shared point"
        | P256.Point { x; _ } -> x )
;;

let%test "export_public_key_raw format" =
    let raw =
        export_public_key_raw
          { curve = `P256; point = P256.scalar_mult_base Z.one }
    in
    Bytes.length raw = 65 && Bytes.get_uint8 raw 0 = 0x04
;;

let%test "export_public_key_raw generated key has valid format" =
    let kp = generate_key ~named_curve:`P256 in
    let raw = export_public_key_raw kp.public_key in
    Bytes.length raw = 65 && Bytes.get_uint8 raw 0 = 0x04
;;

let%test "export_private_key_raw format" =
    let kp = generate_key ~named_curve:`P256 in
    let raw = export_private_key_raw kp.private_key in
    Bytes.length raw = 32
;;

let%test "private key raw round-trip" =
    let kp = generate_key ~named_curve:`P256 in
    let raw = export_private_key_raw kp.private_key in
    let imported = import_private_key_raw ~named_curve:`P256 raw in
    Bytes.equal raw (export_private_key_raw imported)
;;

let%test "derive_bits symmetric" =
    let alice = generate_key ~named_curve:`P256 in
    let bob = generate_key ~named_curve:`P256 in
    let s1 =
        derive_bits ~private_key:alice.private_key ~public_key:bob.public_key
    in
    let s2 =
        derive_bits ~private_key:bob.private_key ~public_key:alice.public_key
    in
    Bytes.equal s1 s2
;;

let%test "derive_bits length is 32 bytes" =
    let alice = generate_key ~named_curve:`P256 in
    let bob = generate_key ~named_curve:`P256 in
    let shared =
        derive_bits ~private_key:alice.private_key ~public_key:bob.public_key
    in
    Bytes.length shared = 32
;;
