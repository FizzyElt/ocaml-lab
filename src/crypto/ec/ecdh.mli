type named_curve = [ `P256 ]

type public_key =
  { curve : named_curve
  ; point : P256.point
  }

type private_key =
  { curve : named_curve
  ; d : P256.scalar
  }

type key_pair =
  { public_key : public_key
  ; private_key : private_key
  }

val generate_key : named_curve:named_curve -> key_pair

val import_public_key_raw : named_curve:named_curve -> bytes -> public_key

val export_public_key_raw : public_key -> bytes

val import_private_key_raw : named_curve:named_curve -> bytes -> private_key

val export_private_key_raw : private_key -> bytes

val derive_bits : private_key:private_key -> public_key:public_key -> bytes
