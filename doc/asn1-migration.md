# Standalone ASN.1 dependency

Heimdal no longer builds or installs the generic ASN.1 compiler and runtime.
They are maintained by the separate `asn1_compile` project, which preserves
the history of the former `lib/asn1` subtree.

## Build contract

Heimdal requires `libasn1 >= 0.1.0`, discovered through `pkg-config`, and a
native `asn1_compile >= 0.1.0` program advertising generated-output
compatibility version 1.  Package and output-contract versions are checked
separately so an otherwise newer compiler cannot silently generate an
incompatible source contract.  Use `--with-asn1-prefix=DIR` when both are
installed below a non-standard prefix, or
`--with-asn1-compiler=PATH`/`ASN1_COMPILE=PATH` to select the build-machine
compiler separately.

Cross builds must use a native compiler to generate C and a target `libasn1`
to compile and link that C.  `--with-cross-tools=DIR` remains a fallback for
locating the native compiler, but the explicit compiler option is preferred.
Release archives intentionally do not contain a bundled compiler or runtime.

## Protocol ownership and ABI

Application schemas remain in Heimdal and their generated code is linked into
the library that implements the protocol:

| Owner | Modules |
| --- | --- |
| `libkrb5` | Kerberos, PKINIT, and KX509 |
| `libhx509` | PKIX, CMS, OCSP, PKCS, RFC 4108, and related certificate modules |
| `libgssapi` | GSSAPI, SPNEGO, and PKU2U |
| `libhdb` | HDB |
| `libkadm5` | password-change protocol data |
| `libkdc` | digest service protocol data |

Consequently, protocol codec and descriptor symbols formerly exported by
Heimdal's `libasn1.so` are now exported by their owner library.  The external
`libasn1.so.8` contains only schema-neutral DER/BER and generated-code support.
There is no compatibility library that restores the old protocol-symbol
placement; downstream link lines must name the owning Heimdal library.

Each owner registers its generated symbolic OIDs with the initially empty
runtime registry during library context initialization.  This preserves
symbolic OID parsing and printing without putting a protocol catalog in the
standalone support library.
