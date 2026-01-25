(lang dune 3.21)

(name ocaml-lab)

(generate_opam_files false)

(source
 (github FizzyElt/ocaml-lab))

(license LICENSE)

(package
 (name ocaml-lab)
 (allow_empty)
 (synopsis "A short synopsis")
 (description "A longer description")
 (depends ocaml ppx_inline_test)
 (tags
  ("add topics" "to describe" your project)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
