type scalar

type point =
  | Infinity
  | Point of
      { x : bytes
      ; y : bytes
      }

val coordinate_size_bytes : int

val scalar_size_bytes : int

val scalar_of_bytes : bytes -> scalar

val scalar_to_bytes : scalar -> bytes

val point_of_uncompressed_bytes : bytes -> point

val point_to_uncompressed_bytes : point -> bytes

val is_on_curve : point -> bool

val is_valid_public_key : point -> bool

val scalar_mult_base : scalar -> point

val scalar_mult : scalar -> point -> point
