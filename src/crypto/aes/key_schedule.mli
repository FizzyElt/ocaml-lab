open Variant

type word = private bytes

val key_expansion : variant:variant -> bytes -> word array

val round_key_of_words : word array -> int -> bytes
