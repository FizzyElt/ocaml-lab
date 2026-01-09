module type M = sig
  val to_bytes : string -> bytes
  val of_bytes : bytes -> string
end

module Hex : M = struct
  let hex_value (c : char) : int =
      match c with
      | '0' .. '9' -> Char.code c - Char.code '0'
      | 'a' .. 'f' -> 10 + Char.code c - Char.code 'a'
      | 'A' .. 'F' -> 10 + Char.code c - Char.code 'A'
      | _ -> invalid_arg "hex_value"
  ;;

  let to_bytes (s : string) : bytes =
      let len = String.length s in
      if len mod 2 <> 0 then invalid_arg "bytes_of_hex: odd length";
      let out = Bytes.create (len / 2) in
      for i = 0 to (len / 2) - 1 do
        let hi = hex_value s.[2 * i] in
        let lo = hex_value s.[(2 * i) + 1] in
        Bytes.set_uint8 out i ((hi lsl 4) lor lo)
      done;
      out
  ;;

  let of_bytes (b : bytes) : string =
      let hex = "0123456789abcdef" in
      let out = Bytes.create (Bytes.length b * 2) in
      for i = 0 to Bytes.length b - 1 do
        let v = Bytes.get_uint8 b i in
        Bytes.set out (2 * i) hex.[v lsr 4];
        Bytes.set out ((2 * i) + 1) hex.[v land 0xf]
      done;
      Bytes.to_string out
  ;;
end

include Hex
