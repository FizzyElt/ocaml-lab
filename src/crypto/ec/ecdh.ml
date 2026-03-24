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

let generate_key ~(named_curve : named_curve) : key_pair = failwith ""

let import_public_key_raw ~(named_curve : named_curve) (raw : bytes)
  : public_key
  =
    failwith ""
;;

let export_public_key_raw (pub_key : public_key) : bytes = failwith ""

let import_private_key_raw ~(named_curve : named_curve) (raw : bytes)
  : private_key
  =
    failwith ""
;;

let export_private_key_raw (priv_key : private_key) : bytes = failwith ""

let derive_bits ~(private_key : private_key) ~(public_key : public_key) : bytes =
    failwith ""
;;
