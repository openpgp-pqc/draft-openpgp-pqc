---
title: "Post-Quantum Cryptography in OpenPGP"
abbrev: "PQC in OpenPGP"
category: info

docname: draft-ietf-openpgp-pqc-latest
submissiontype: IETF
v: 3
area: sec
workgroup: Network Working Group
keyword: Internet-Draft
venue:
  group: WG
  type: Working Group
  mail: openpgp@ietf.org
  arch: "https://mailarchive.ietf.org/arch/browse/openpgp/"
  repo: "https://github.com/openpgp-pqc/draft-openpgp-pqc"

author:
 -
    ins: S. Kousidis
    name: Stavros Kousidis
    org: BSI
    country: Germany
    email: kousidis.ietf@gmail.com
 -
    ins: J. Roth
    name: Johannes Roth
    org: MTG AG
    country: Germany
    email: johannes.roth@mtg.de
 -
    ins: F. Strenzke
    name: Falko Strenzke
    org: MTG AG
    country: Germany
    email: falko.strenzke@mtg.de
 -
    ins: A. Wussler
    name: Aron Wussler
    org: Proton AG
    country: Switzerland
    email: aron@wussler.it

normative:

  RFC7748:

  RFC8032:

  RFC3394:

  RFC9580:

informative:

  I-D.ietf-pquip-pqt-hybrid-terminology:

  NIST-PQC:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
    title: Post-Quantum Cryptography Standardization
    author:
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: Y. Liu
        name: Yi-Kai Liu
    date: December 2016

  NISTIR-8413:
    target: https://doi.org/10.6028/NIST.IR.8413-upd1
    title: Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process
    author:
      -
        ins: G. Alagic
        name: Gorjan Alagic
      -
        ins: D. Apon
        name: Daniel Apon
      -
        ins: D. Cooper
        name: David Cooper
      -
        ins: Q. Dang
        name: Quynh Dang
      -
        ins: T. Dang
        name: Thinh Dang
      -
        ins: J. Kelsey
        name: John Kelsay
      -
        ins: J. Lichtinger
        name: Jacob Lichtinger
      -
        ins: C. Miller
        name: Carl Miller
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: R. Peralta
        name: Rene Peralta
      -
        ins: R. Perlner
        name: Ray Perlner
      -
        ins: A. Robinson
        name: Angela Robinson
      -
        ins: D. Smith-Tone
        name: Daniel Smith-Tone
      -
        ins: Y. Liu
        name: Yi-Kai Liu
    date: September 2022
    seriesinfo:
      NIST IR 8413

  SP800-56C:
    target: https://doi.org/10.6028/NIST.SP.800-56Cr2
    title: Recommendation for Key-Derivation Methods in Key-Establishment Schemes
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: R. Davis
        name: Richard Davis
    date: August 2020
    seriesinfo:
      NIST Special Publication 800-56C Rev. 2

  FIPS-203:
      target: https://doi.org/10.6028/NIST.FIPS.203
      title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2024

  FIPS-204:
      target: https://doi.org/10.6028/NIST.FIPS.204
      title: Module-Lattice-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2024

  FIPS-205:
      target: https://doi.org/10.6028/NIST.FIPS.205
      title: Stateless Hash-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2024

  BCD+24:
    target: https://doi.org/10.62056/a3qj89n4e
    title: X-Wing The Hybrid KEM You’ve Been Looking For
    author:
      -
        ins: M. Barbosa
        name: Manuel Barbosa
      -
        ins: D. Connolly
        name: Deirdre Connolly
      -
        ins: J. D. Duarte
        name: Joao Diogo Duarte
      -
        ins: A. Kaiser
        name: Aaron Kaiser
      -
        ins: P. Schwabe
        name: Peter Schwabe
      -
        ins: K. Varner
        name: Karoline Varner
      -
        ins: B. Westerbaan
        name: Bas Westerbaan
    date: 2024

  ABH+21:
    target: https://doi.org/10.1007/978-3-030-77870-5_4
    title: Analysing the HPKE Standard
    author:
      -
        ins: J. Alwen
        name: Joel Alwen
      -
        ins: B. Blanchet
        name: Bruno Blanchet
      -
        ins: E. Hauck
        name: Eduard Hauck
      -
        ins: E. Kiltz
        name: Eike Kiltz
      -
        ins: B. Lipp
        name: Benjamin Lipp
      -
        ins: D. Riepel
        name: Doreen Riepl
    date: 2021

--- abstract

This document defines a post-quantum public-key algorithm extension for the OpenPGP protocol.
Given the generally assumed threat of a cryptographically relevant quantum computer, this extension provides a basis for long-term secure OpenPGP signatures and ciphertexts.
Specifically, it defines composite public-key encryption based on ML-KEM (formerly CRYSTALS-Kyber), composite public-key signatures based on ML-DSA (formerly CRYSTALS-Dilithium), both in combination with elliptic curve cryptography, and SLH-DSA (formerly SPHINCS+) as a standalone public key signature scheme.

--- middle

# Introduction

The OpenPGP protocol supports various traditional public-key algorithms based on the factoring or discrete logarithm problem.
As the security of algorithms based on these mathematical problems is endangered by the advent of quantum computers, there is a need to extend OpenPGP by algorithms that remain secure in the presence of quantum computers.

Such cryptographic algorithms are referred to as post-quantum cryptography.
The algorithms defined in this extension were chosen for standardization by the National Institute of Standards and Technology (NIST) in mid 2022 {{NISTIR-8413}} as the result of the NIST Post-Quantum Cryptography Standardization process initiated in 2016 {{NIST-PQC}}.
Namely, these are ML-KEM {{FIPS-203}} as a Key Encapsulation Mechanism (KEM), a KEM being a modern building block for public-key encryption, and ML-DSA {{FIPS-204}} as well as SLH-DSA {{FIPS-205}} as signature schemes.

For the two ML-* schemes, this document follows the conservative strategy to deploy post-quantum in combination with traditional schemes such that the security is retained even if all schemes but one in the combination are broken.
In contrast, the stateless hash-based signature scheme SLH-DSA is considered to be sufficiently well understood with respect to its security assumptions in order to be used standalone.
To this end, this document specifies the following new set: SLH-DSA standalone and the two ML-* as composite with ECC-based KEM and digital signature schemes.
Here, the term "composite" indicates that any data structure or algorithm pertaining to the combination of the two components appears as single data structure or algorithm from the protocol perspective.

The document specifies the conventions for interoperability between compliant OpenPGP implementations that make use of this extension and the newly defined algorithms or algorithm combinations.

## Conventions used in this Document

### Terminology for Multi-Algorithm Schemes

The terminology in this document is oriented towards the definitions in {{I-D.ietf-pquip-pqt-hybrid-terminology}}.
Specifically, the terms "multi-algorithm", "composite" and "non-composite" are used in correspondence with the definitions therein.
The abbreviation "PQ" is used for post-quantum schemes.
To denote the combination of post-quantum and traditional schemes, the abbreviation "PQ/T" is used.
The short form "PQ(/T)" stands for PQ or PQ/T.

## Post-Quantum Cryptography

This section describes the individual post-quantum cryptographic schemes.
All schemes listed here are believed to provide security in the presence of a cryptographically relevant quantum computer.
However, the mathematical problems on which the two ML-* schemes and SLH-DSA are based, are fundamentally different, and accordingly the level of trust commonly placed in them as well as their performance characteristics vary.

### ML-KEM {#mlkem-intro}

ML-KEM [FIPS-203] is based on the hardness of solving the Learning with Errors problem in module lattices (MLWE).
The scheme is believed to provide security against cryptanalytic attacks by classical as well as quantum computers.
This specification defines ML-KEM only in composite combination with ECDH encryption schemes in order to provide a pre-quantum security fallback.

### ML-DSA {#mldsa-intro}

ML-DSA [FIPS-204] is a signature scheme that, like ML-KEM, is based on the hardness of solving the Learning With Errors problem and a variant of the Short Integer Solution problem in module lattices (MLWE and SelfTargetMSIS).
Accordingly, this specification only defines ML-DSA in composite combination with EdDSA signature schemes.

### SLH-DSA

SLH-DSA [FIPS-205] is a stateless hash-based signature scheme.
Its security relies on the hardness of finding preimages for cryptographic hash functions.
This feature is generally considered to be a high security guarantee.
Therefore, this specification defines SLH-DSA as a standalone signature scheme.

In deployments the performance characteristics of SLH-DSA should be taken into account.
We refer to {{performance-considerations}} for a discussion of the performance characteristics of this scheme.

## Elliptic Curve Cryptography

The ECDH encryption is defined here as a KEM via X25519 and X448 which are defined in [RFC7748].
EdDSA as defined in [RFC8032] is used as the elliptic curve-based digital signature scheme.

## Standalone and Multi-Algorithm Schemes {#multi-algo-schemes}

This section provides a categorization of the new algorithms and their combinations.

### Standalone and Composite Multi-Algorithm Schemes {#composite-multi-alg}

This specification introduces new cryptographic schemes, which can be categorized as follows:

 - PQ/T multi-algorithm public-key encryption, namely a composite combination of ML-KEM with an ECDH KEM,

 - PQ/T multi-algorithm digital signature, namely composite combinations of ML-DSA with EdDSA signature schemes,

 - PQ digital signature, namely SLH-DSA as a standalone cryptographic algorithm.

For each of the composite schemes, this specification mandates that the consuming party has to successfully perform the cryptographic algorithms for each of the component schemes used in a cryptographic message, in order for the message to be deciphered and considered as valid.
This means that all component signatures must be verified successfully in order to achieve a successful verification of the composite signature.
In the case of the composite public-key decryption, each of the component KEM decapsulation operations must succeed.

### Non-Composite Algorithm Combinations {#non-composite-multi-alg}

As the OpenPGP protocol [RFC9580] allows for multiple signatures to be applied to a single message, it is also possible to realize non-composite combinations of signatures.
Furthermore, multiple OpenPGP signatures may be combined on the application layer.
These latter two cases realize non-composite combinations of signatures.
{{multiple-signatures}} specifies how implementations should handle the verification of such combinations of signatures.

Furthermore, the OpenPGP protocol also allows parallel encryption to different keys by using multiple PKESK packets, thus realizing non-composite multi-algorithm public-key encryption.

# Supported Public Key Algorithms

This section specifies the composite ML-KEM + ECDH and ML-DSA + EdDSA schemes as well as the standalone SLH-DSA signature scheme.
All of these schemes are fully specified via their algorithm ID, i.e., they are not parametrized.

## Algorithm Specifications

For signatures, the following (composite) signature schemes are specified:

{: title="Signature algorithm specifications" #sig-alg-specs}
ID                    | Algorithm                        | Requirement | Definition
---------------------:| -------------------------------- | ----------- | --------------------
30                    | ML-DSA-65+Ed25519                | MUST        | {{ecc-mldsa}}
31                    | ML-DSA-87+Ed448                  | SHOULD      | {{ecc-mldsa}}
32                    | SLH-DSA-SHAKE-128s               | MAY         | {{slhdsa}}
33                    | SLH-DSA-SHAKE-128f               | MAY         | {{slhdsa}}
34                    | SLH-DSA-SHAKE-256s               | MAY         | {{slhdsa}}

For encryption, the following composite KEM schemes are specified:

{: title="KEM algorithm specifications" #kem-alg-specs}
ID | Algorithm                        | Requirement | Definition
---| -------------------------------- | ----------- | --------------------
35 | ML-KEM-768+X25519                | MUST        | {{ecc-mlkem}}
36 | ML-KEM-1024+X448                 | SHOULD      | {{ecc-mlkem}}

# Algorithm Combinations

## Composite KEMs {#composite-kem}

The ML-KEM + ECDH public-key encryption involves both the ML-KEM and an ECDH KEM in an a priori non-separable manner.
This is achieved via KEM combination, i.e. both key encapsulations/decapsulations are performed in parallel, and the resulting key shares are fed into a key combiner to produce a single shared secret for message encryption.

As explained in {{non-composite-multi-alg}}, the OpenPGP protocol inherently supports parallel encryption to different keys.
Note that the confidentiality of a message is not post-quantum secure when encrypting to different keys if at least one key does not support PQ(/T) encryption schemes.

## Composite Signatures

The ML-DSA + EdDSA signature consists of independent ML-DSA and EdDSA signatures, and an implementation MUST successfully validate both signatures to state that the ML-DSA + EdDSA signature is valid.

## Multiple Signatures {#multiple-signatures}

The OpenPGP message format allows multiple signatures of a message, i.e. the attachment of multiple signature packets.

An implementation MAY sign a message with a traditional key and a PQ(/T) key from the same sender.
This ensures backwards compatibility due to [[RFC9580, Section 5.2.5]](https://www.rfc-editor.org/rfc/rfc9580#section-5.2.5), since a legacy implementation without PQ(/T) support can fall back on the traditional signature.

Newer implementations with PQ(/T) support MAY ignore the traditional signature(s) during validation.

Implementations SHOULD consider the message correctly signed if at least one of the non-ignored signatures validates successfully.
This is an interpretation of [[RFC9580, Section 5.2.5]](https://www.rfc-editor.org/rfc/rfc9580#section-5.2.5).

## ECC requirements

Even though the zero point, also called the point at infinity, may occur as a result of arithmetic operations on points of an elliptic curve, it MUST NOT appear in any ECC data structure defined in this document.

Furthermore, when performing the explicitly listed operations in {{x25519-kem}} or {{x448-kem}} it is REQUIRED to follow the specification and security advisory mandated from the respective elliptic curve specification.

## Key version binding

All (PQ/T) asymmetric algorithms are to be used only in v6 (and newer) keys and certificates, with the single exception of ML-KEM-768+X25519 (algorithm ID 35), which is also allowed in v4 encryption-capable subkeys.
This permits the keyholder of an existing v4 certificate to add such a subkey to defend against store-now, decrypt-later attacks from quantum computers without moving to a new primary key.

# Composite KEM schemes

## Building Blocks

### ECDH KEMs {#ecc-kem}

In this section we define the encryption, decryption, and data formats for the ECDH component of the composite algorithms.

{{tab-ecdh-cfrg-artifacts}} describes the ECDH-KEM parameters and artifact lengths.
The artifacts in {{tab-ecdh-cfrg-artifacts}} follow the encodings described in [RFC7748].

{: title="Montgomery curves parameters and artifact lengths" #tab-ecdh-cfrg-artifacts}
|                        | X25519                                     | X448                                       |
|------------------------|--------------------------------------------|--------------------------------------------|
| Algorithm ID reference | 35                                         | 36                                         |
| Field size             | 32 octets                                  | 56 octets                                  |
| ECDH-KEM               | x25519Kem ({{x25519-kem}})                 | x448Kem ({{x448-kem}})                     |
| ECDH public key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH secret key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH ephemeral         | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH key share         | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |

The various procedures to perform the operations of an ECDH KEM are defined in the following subsections.
Specifically, each of these subsections defines the instances of the following operations:

    (ecdhCipherText, ecdhKeyShare) <- ECDH-KEM.Encaps(ecdhPublicKey)

and

    (ecdhKeyShare) <- ECDH-KEM.Decaps(ecdhSecretKey, ecdhCipherText, ecdhPublicKey)

To instantiate `ECDH-KEM`, one must select a parameter set from {{tab-ecdh-cfrg-artifacts}}.

#### X25519-KEM {#x25519-kem}

The encapsulation and decapsulation operations of `x25519kem` are described using the function `X25519()` and encodings defined in [RFC7748].
The `ecdhSecretKey` is denoted as `r`, the `ecdhPublicKey` as `R`, they are subject to the equation `R = X25519(r, U(P))`.
Here, `U(P)` denotes the u-coordinate of the base point of Curve25519.

The operation `x25519Kem.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X25519(v,U(P))` where `v` is a randomly generated octet string with a length of 32 octets

 2. Compute the shared coordinate `X = X25519(v, R)` where `R` is the recipient's public key `ecdhPublicKey`

 3. Set the output `ecdhCipherText` to `V`

 4. Set the output `ecdhKeyShare` to `X`

The operation `x25519Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X25519(r, V)`, where `r` is the `ecdhSecretKey` and `V` is the `ecdhCipherText`

 2. Set the output `ecdhKeyShare` to `X`

#### X448-KEM {#x448-kem}

The encapsulation and decapsulation operations of `x448kem` are described using the function `X448()` and encodings defined in [RFC7748].
The `ecdhSecretKey` is denoted as `r`, the `ecdhPublicKey` as `R`, they are subject to the equation `R = X25519(r, U(P))`.
Here, `U(P)` denotes the u-coordinate of the base point of Curve448.

The operation `x448.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X448(v,U(P))` where `v` is a randomly generated octet string with a length of 56 octets

 2. Compute the shared coordinate `X = X448(v, R)` where `R` is the recipient's public key `ecdhPublicKey`

 3. Set the output `ecdhCipherText` to `V`

 4. Set the output `ecdhKeyShare` to `X`

The operation `x448Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X448(r, V)`, where `r` is the `ecdhSecretKey` and `V` is the `ecdhCipherText`

 2. Set the output `ecdhKeyShare` to `X`

### ML-KEM {#mlkem-ops}

ML-KEM features the following operations:

    (mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemPublicKey)

and

    (mlkemKeyShare) <- ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)

The above are the operations `ML-KEM.Encaps` and `ML-KEM.Decaps` defined in [FIPS-203].
Note that `mlkemPublicKey` is the encapsulation and `mlkemSecretKey` is the decapsulation key.

ML-KEM has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mlkem-artifacts}}.
All artifacts are encoded as defined in [FIPS-203].

{: title="ML-KEM parameters artifact lengths in octets" #tab-mlkem-artifacts}
Algorithm ID reference | ML-KEM      | Public key | Secret key | Ciphertext | Key share
----------------------:| ----------- | ---------- | ---------- | ---------- | ---------
35                     | ML-KEM-768  | 1184       | 64         | 1088       | 32
36                     | ML-KEM-1024 | 1568       | 64         | 1568       | 32

To instantiate `ML-KEM`, one must select a parameter set from the column "ML-KEM" of {{tab-mlkem-artifacts}}.

The procedure to perform `ML-KEM.Encaps()` is as follows:

 1. Invoke `(mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemPublicKey)`, where `mlkemPublicKey` is the recipient's public key

 2. Set `mlkemCipherText` as the ML-KEM ciphertext

 3. Set `mlkemKeyShare` as the ML-KEM symmetric key share

The procedure to perform `ML-KEM.Decaps()` is as follows:

 1. Invoke `mlkemKeyShare <-  ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 2. Set `mlkemKeyShare` as the ML-KEM symmetric key share

## Composite Encryption Schemes with ML-KEM {#ecc-mlkem}

{{kem-alg-specs}} specifies the following ML-KEM + ECDH composite public-key encryption schemes:

{: title="ML-KEM + ECDH composite schemes" #tab-mlkem-ecc-composite}
Algorithm ID reference                   | ML-KEM       | ECDH-KEM
----------------------------------------:| ------------ | ---------
35                                       | ML-KEM-768   | x25519Kem
36                                       | ML-KEM-1024  | x448Kem

The ML-KEM + ECDH composite public-key encryption schemes are built according to the following principal design:

 - The ML-KEM encapsulation algorithm is invoked to create an ML-KEM ciphertext together with an ML-KEM symmetric key share.

 - The encapsulation algorithm of an ECDH KEM, namely X25519-KEM or X448-KEM, is invoked to create an ECDH ciphertext together with an ECDH symmetric key share.

 - A Key-Encryption-Key (KEK) is computed as the output of a key combiner that receives as input both of the above created symmetric key shares and the protocol binding information.

 - The session key for content encryption is then wrapped as described in {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The PKESK packet's algorithm-specific parts are made up of the ML-KEM ciphertext, the ECDH ciphertext, and the wrapped session key.


### Key combiner {#kem-key-combiner}

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure MUST be used to compute the KEK that wraps a session key.
The construction is a key derivation function compliant to {{SP800-56C}}, Section 4, based on SHA3-256.
It is given by the following algorithm, which computes the key encryption key `KEK` that is used to wrap, i.e., encrypt, the session key.


    //   multiKeyCombine(
    //       mlkemKeyShare, ecdhKeyShare,
    //       ecdhCipherText, ecdhPublicKey,
    //       algId
    //   )
    //
    //   Input:
    //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
    //   ecdhKeyShare    - the ECDH key share encoded as an octet string
    //   ecdhCipherText  - the ECDH ciphertext encoded as an octet string
    //   ecdhPublicKey   - the ECDH public key of the recipient as an octet string
    //   algId           - the OpenPGP algorithm ID of the public-key encryption algorithm

    KEK = SHA3-256(
              mlkemKeyShare || ecdhKeyShare ||
              ecdhCipherText || ecdhPublicKey ||
              algId || domSep || len(domSep)
          )
    return KEK

The value `domSep` is a constant set to the UTF-8 encoding of the string "OpenPGPCompositeKDFv1", i.e.

    domSep := 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31

Here `len(domSep)` is the single octet with the value equal to the octet-length of `domSep`, i.e., decimal 21.

### Key generation procedure {#ecc-mlkem-generation}

The implementation MUST generate the ML-KEM and the ECDH component keys independently.
ML-KEM key generation follows the specification [FIPS-203] and the artifacts are encoded as fixed-length octet strings as defined in {{mlkem-ops}}.
For ECDH this is done following the relative specification in {{RFC7748}}, and encoding the outputs as fixed-length octet strings in the format specified in {{tab-ecdh-cfrg-artifacts}}.

### Encryption procedure {#ecc-mlkem-encryption}

The procedure to perform public-key encryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the recipient's authenticated public-key packet `pkComposite` and `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite` and set it as `algId`

 3. Extract the `ecdhPublicKey` and `mlkemPublicKey` component from the algorithm specific data encoded in `pkComposite` with the format specified in {{mlkem-ecc-key}}.

 4. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 5. Compute `(ecdhCipherText, ecdhKeyShare) := ECDH-KEM.Encaps(ecdhPublicKey)`

 6. Compute `(mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)`

 7. Compute `KEK := multiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, algId)` as defined in {{kem-key-combiner}}

 8. Compute `C := AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}} that includes a 64 bit integrity check

 9. Output the algorithm specific part of the PKESK as `ecdhCipherText || mlkemCipherText || len(C, symAlgId) (|| symAlgId)  || C`, where both `symAlgId` and `len(C, symAlgId)` are single octet fields, `symAlgId` denotes the symmetric algorithm ID used and is present only for a v3 PKESK, and `len(C, symAlgId)` denotes the combined octet length of the fields specified as the arguments.

### Decryption procedure

The procedure to perform public-key decryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID as `algId` and the wrapped session key as `encryptedKey`

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `ecdhSecretKey` and `mlkemSecretKey` from the algorithm specific data of the own secret key encoded in the format specified in {{mlkem-ecc-key}}

 5. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 6. Parse `ecdhCipherText`, `mlkemCipherText`, and `C` from `encryptedKey` encoded as `ecdhCipherText || mlkemCipherText || len(C,symAlgId) (|| symAlgId) || C` as specified in {{ecc-mlkem-pkesk}}, where `symAlgId` is present only in the case of a v3 PKESK.

 7. Compute `(ecdhKeyShare) := ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey, ecdhPublicKey)`

 8. Compute `(mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 9. Compute `KEK := multiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, algId)` as defined in {{kem-key-combiner}}

 10. Compute `sessionKey := AESKeyUnwrap(KEK, C)`  with AES-256 as per {{RFC3394}}, aborting if the 64 bit integrity check fails

 11. Output `sessionKey`

## Packet specifications

### Public-Key Encrypted Session Key Packets (Tag 1) {#ecc-mlkem-pkesk}

The algorithm-specific fields consists of the output of the encryption procedure described in {{ecc-mlkem-encryption}}:

 - A fixed-length octet string representing an ECDH ephemeral public key in the format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the ML-KEM ciphertext, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

 - A one-octet size of the following fields.

 - Only in the case of a v3 PKESK packet: a one-octet symmetric algorithm identifier.

 - The wrapped session key represented as an octet string.

Note that like in the case of the algorithms X25519 and X448 specified in [RFC9580], for the ML-KEM composite schemes, in the case of a v3 PKESK packet, the symmetric algorithm identifier is not encrypted.
Instead, it is placed in plaintext after the `mlkemCipherText` and before the length octet preceding the wrapped session key.
In the case of v3 PKESK packets for ML-KEM composite schemes, the symmetric algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8 or 9).

In the case of a v3 PKESK, a receiving implementation MUST check if the length of the unwrapped symmetric key matches the symmetric algorithm identifier, and abort if this is not the case.

Implementations MUST NOT use the obsolete Symmetrically Encrypted Data packet (tag 9) to encrypt data protected with the algorithms described in this document.

### Key Material Packets {#mlkem-ecc-key}

The composite ML-KEM-768 + X25519 (algorithm ID 35) MUST be used only with v4 or v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

The composite ML-KEM-1024 + X448 (algorithm ID 36) MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an EC point public key, in the point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM public key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded secret scalar, whose encoding and length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM secret key in seed format, whose length is 64 octets (compare {{tab-mlkem-artifacts}}).
   The seed format is defined in accordance with [FIPS-203], Section 3.3.
   Namely, the secret key is given by the concatenation of the values of `d`  and `z`, generated in steps 1 and 2 of `ML-KEM.KeyGen` [FIPS-203], each of a length of 32 octets.
   Upon parsing the secret key format, or before using the secret key, for the expansion of the key, the function `ML-KEM.KeyGen_internal` [FIPS-203] has to be invoked with the parsed values of `d` and `z` as input.

# Composite Signature Schemes

## Building blocks

### EdDSA-Based signatures {#eddsa-signature}

Throughout this specification EdDSA refers to the PureEdDSA variant defined in
[RFC8032].

To sign and verify with EdDSA the following operations are defined:

    (eddsaSignature) <- EdDSA.Sign(eddsaSecretKey, dataDigest)

and

    (verified) <- EdDSA.Verify(eddsaPublicKey, eddsaSignature, dataDigest)

The public and secret key, as well as the signature MUST be encoded according to [RFC8032] as fixed-length octet strings.
The following table describes the EdDSA parameters and artifact lengths:

{: title="EdDSA parameters and artifact lengths in octets" #tab-eddsa-artifacts}
Algorithm ID reference | Curve   | Field size | Public key | Secret key | Signature
----------------------:| ------- | ---------- | ---------- | ---------- | ---------
30                     | Ed25519 | 32         | 32         | 32         | 64
31                     | Ed448   | 57         | 57         | 57         | 114

### ML-DSA signatures {#mldsa-signature}

Throughout this specification ML-DSA refers to the default pure and hedged version of ML-DSA defined in [FIPS-204].

For ML-DSA signature generation the default hedged version of the algorithm `ML-DSA.Sign` given in [FIPS-204] is used.
That is, to sign with ML-DSA the following operation is defined:

    (mldsaSignature) <- ML-DSA.Sign(mldsaSecretKey, dataDigest)

For ML-DSA signature verification the algorithm `ML-DSA.Verify` given in [FIPS-204] is used.
That is, to verify with ML-DSA the following operation is defined:

    (verified) <- ML-DSA.Verify(mldsaPublicKey, dataDigest, mldsaSignature)

ML-DSA has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mldsa-artifacts}}.
All artifacts are encoded as defined in [FIPS-204].

{: title="ML-DSA parameters and artifact lengths in octets" #tab-mldsa-artifacts}
Algorithm ID reference | ML-DSA    | Public key | Secret key | Signature value
----------------------:| --------- | -----------| ---------- | ---------------
30                     | ML-DSA-65 | 1952       | 32         | 3309
31                     | ML-DSA-87 | 2592       | 32         | 4627

## Composite Signature Schemes with ML-DSA {#ecc-mldsa}

### Key generation procedure {#ecc-mldsa-generation}

The implementation MUST generate the ML-DSA and the EdDSA component keys independently.
ML-DSA key generation follows the specification [FIPS-204] and the artifacts are encoded as fixed-length octet strings as defined in {{mldsa-signature}}.
For EdDSA this is done following the relative specification in {{RFC7748}}, and encoding the artifacts as specified in {{eddsa-signature}} as fixed-length octet strings.

### Signature Generation

To sign a message `M` with ML-DSA + EdDSA the following sequence of operations has to be performed:

 1. Generate `dataDigest` according to [[RFC9580, Section 5.2.4]](https://www.rfc-editor.org/rfc/rfc9580#section-5.2.4)

 2. Create the EdDSA signature over `dataDigest` with `EdDSA.Sign()` from {{eddsa-signature}}

 3. Create the ML-DSA signature over `dataDigest` with `ML-DSA.Sign()` from {{mldsa-signature}}

 4. Encode the EdDSA and ML-DSA signatures according to the packet structure given in {{ecc-mldsa-sig-packet}}.

### Signature Verification

To verify an ML-DSA + EdDSA signature the following sequence of operations has to be performed:

 1. Verify the EdDSA signature with `EdDSA.Verify()` from {{eddsa-signature}}

 2. Verify the ML-DSA signature with `ML-DSA.Verify()` from {{mldsa-signature}}

As specified in {{composite-signatures}} an implementation MUST validate both signatures, i.e. EdDSA and ML-DSA, successfully to state that a composite ML-DSA + EdDSA signature is valid.

## Packet Specifications

### Signature Packet (Tag 2) {#ecc-mldsa-sig-packet}

The composite ML-DSA + EdDSA schemes MUST be used only with v6 signatures, as defined in [RFC9580], or newer versions defined by updates of that document.

The algorithm-specific v6 signature parameters for ML-DSA + EdDSA signatures consist of:

 - A fixed-length octet string representing the EdDSA signature, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

### Key Material Packets

The composite ML-DSA + EdDSA schemes MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

The algorithm-specific public key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA public key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific secret key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA secret key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key in seed format, whose length is 32 octets (compare {{tab-mldsa-artifacts}}).
   The seed format is defined in accordance with [FIPS-204], Section 3.6.3.
   Namely, the secret key is given by the value `xi` generated in step 1 of `ML-DSA.KeyGen` [FIPS-204].
   Upon parsing the secret key format, or before using the secret key, for the expansion of the key, the function `ML-DSA.KeyGen_internal` [FIPS-204] has to be invoked with the parsed value of `xi` as input.

# SLH-DSA

Throughout this specification SLH-DSA refers to the default pure and hedged version of SLH-DSA defined in [FIPS-205].

## The SLH-DSA Algorithms {#slhdsa}

The following table lists the group of algorithm code points for the SLH-DSA signature scheme and the corresponding artifact lengths.
This group of algorithms is henceforth referred to as "SLH-DSA code points".

{: title="SLH-DSA algorithm code points and the corresponding artifact lengths in octets." #slhdsa-artifact-lengths}
Algorithm ID reference   |  SLH-DSA public key | SLH-DSA secret key | SLH-DSA signature
----------------------:  |  ------------------ | ------------------ | ------------------
32                       |  32                 | 64                 | 7856
33                       |  32                 | 64                 | 17088
34                       |  64                 | 128                | 29792

### Key generation

SLH-DSA key generation is performed via the algorithm `SLH-DSA.KeyGen` as specified in {{FIPS-205}}, and the artifacts are encoded as fixed-length octet strings as defined in {{slhdsa}}.

### Signature Generation

SLH-DSA signature generation is performed via the default hedged version of the algorithm `SLH-DSA.Sign` as specified in {{FIPS-205}}.

### Signature Verification

SLH-DSA signature verification is performed via the algorithm `SLH-DSA.Verify` as specified in {{FIPS-205}}.

## Packet specifications

###  Signature Packet (Tag 2)

The SLH-DSA algorithms MUST be used only with v6 signatures, as defined in [[RFC9580, Section 5.2.3]](https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3).

The algorithm-specific part of a signature packet for an SLH-DSA algorithm code point consists of:

 - A fixed-length octet string of the SLH-DSA signature value, whose length depends on the algorithm ID in the format specified in {{slhdsa-artifact-lengths}}.

### Key Material Packets

The SLH-DSA algorithms code points MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

The algorithm-specific part of the public key consists of:

 - A fixed-length octet string containing the SLH-DSA public key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

The algorithm-specific part of the secret key consists of:

 - A fixed-length octet string containing the SLH-DSA secret key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

# Notes on Algorithms

## Symmetric Algorithms for SEIPD Packets

Implementations MUST implement `AES-256`.
An implementation SHOULD use `AES-256` in the case of a v1 SEIPD packet, or `AES-256` with any available AEAD mode in the case of a v2 SEIPD packet, if all recipient certificates indicate support for it (explicitly or implicitly).

A certificate that contains a PQ(/T) key SHOULD include `AES-256` in the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket and SHOULD include the pair `AES-256` with `OCB` in the "Preferred AEAD Ciphersuites" subpacket.

If `AES-256` is not explicitly in the list of the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket, and if the certificate contains a PQ(/T) key, it is implicitly at the end of the list.
This is justified since `AES-256` is mandatory to implement.
If `AES-128` is also implicitly added to the list, it is added after `AES-256`.

If the pair `AES-256` with `OCB` is not explicitly in the list of the "Preferred AEAD Ciphersuites" subpacket, and if the certificate contains a PQ(/T) key, it is implicitly at the end of the list.
This is justified since `AES-256` and `OCB` are mandatory to implement.
If the pair `AES-128` with `OCB` is also implicitly added to the list, it is added after the pair `AES-256` with `OCB`.

## Hash Algorithms for Key Binding Signatures

Subkey binding signatures over algorithms described in this document and primary key binding signatures made by algorithms described in this document MUST NOT be made with `MD5`, `SHA-1`, or `RIPEMD-160`.
A receiving implementation MUST treat such a signature as invalid.

# Migration Considerations

The post-quantum KEM algorithms defined in {{kem-alg-specs}} and the signature algorithms defined in {{sig-alg-specs}} are a set of new public key algorithms that extend the algorithm selection of [RFC9580].
During the transition period, the post-quantum algorithms will not be supported by all clients.
Therefore various migration considerations must be taken into account, in particular backwards compatibility to existing implementations that have not yet been updated to support the post-quantum algorithms.

## Encrypting to Traditional and PQ(/T) Keys

As noted in {{composite-kem}}, the confidentiality of a message is not post-quantum secure when using multiple PKESKs if at least one does not use PQ(/T) encryption schemes.
An implementation should not abort the encryption process when encrypting a message to both PQ(/T) and traditional keys to allow for a smooth transition to post-quantum cryptography.

## Signing with Traditional and PQ(/T) Keys

An implementation may sign with both a PQ(/T) and a traditional key using multiple signatures over the same data as described in {{multiple-signatures}}.
Signing only with PQ(/T) key material is not backwards compatible.

## Key generation strategies

It is RECOMMENDED to generate fresh secrets when generating PQ(/T) keys.
Note that reusing key material from existing ECC keys in PQ(/T) keys does not provide backwards compatibility.

An OpenPGP certificate is composed of a certification-capable primary key and one or more subkeys for signature, encryption, and authentication.
Two migration strategies are recommended:

1. Generate two independent certificates, one for PQ(/T)-capable implementations, and one for legacy implementations.
   Implementations not understanding PQ(/T) certificates can use the legacy certificate, while PQ(/T)-capable implementations can also use the newer certificate.
   This allows having a traditional certificate for compatibility and a v6 PQ(/T) certificate, at a greater complexity in key distribution.

2. Attach PQ(/T) encryption or signature subkeys to an existing traditional v6 OpenPGP certificate.
   Implementations understanding PQ(/T) will be able to parse and use the subkeys, while PQ(/T)-incapable implementations can gracefully ignore them.
   This simplifies key distribution, as only one certificate needs to be communicated and verified, but leaves the primary key vulnerable to quantum computer attacks.

# Security Considerations

## Security Aspects of Composite Signatures

When multiple signatures are applied to a message, the question of the protocol's resistance against signature stripping attacks naturally arises.
In a signature stripping attack, an adversary removes one or more of the signatures such that only a subset of the signatures remain in the message at the point when it is verified.
This amounts to a downgrade attack that potentially reduces the value of the signature.
It should be noted that the composite signature schemes specified in this draft are not subject to a signature stripping vulnerability.
This is due to the fact that in any OpenPGP signature, the hashed meta data includes the signature algorithm ID, as specified in [[RFC9580, Section 5.2.4]](https://www.rfc-editor.org/rfc/rfc9580#section-5.2.4).
As a consequence, a component signature taken out of the context of a specific composite algorithm is not a valid signature for any message.

Furthermore, it is also not possible to craft a new signature for a message that was signed twice with a composite algorithm by interchanging (i.e., remixing) the component signatures, which would classify as a weak existential forgery.
This is due to the fact that each v6 signatures also includes a random salt at the start of the hashed meta data, as also specified in the aforementioned reference.

## Key combiner {#sec-key-combiner}

For the key combination in {{kem-key-combiner}} this specification limits itself to the use of SHA3-256 in a construction following {{SP800-56C}}.
A central security notion of a key combiner is IND-CCA2-security. It is argued in [BCD+24] that the key combiner specified in {{kem-key-combiner}} is IND-CCA2-secure if ML-KEM is IND-CCA2-secure or the Strong Diffie-Hellman problem in a nominal group holds. Note that Curve25519 and Curve448 qualify as such nominal groups {{ABH+21}}.

Note that the inclusion of the EC public key in the key combiner also accounts for multi-target attacks against X25519 and X448.

### Domain separation and context binding {#sec-fixed-info}

The `domSep` information defined in {{kem-key-combiner}} provides the domain separation for the key combiner construction.
This ensures that the input keying material is used to generate a KEK for a specific purpose.
Appending the length octet ensures that no collisions can result across different domains, which might be defined in the future.
This is because `domSep || len(domSep)` is guaranteed to result in a suffix-free set of octet strings even if further values should be defined for `dompSep`.
The term "suffix-free" applied to a set of words indicates that no word is the suffix of another.
Thus this property ensures unambiguous parsing of a word from the rear of a string. Unambiguous parseability, in turn, ensures that no collisions can happen on the space of input strings to the key combiner.

The algorithm ID, passed as the `algID` parameter to `multiKeyCombine`, binds the derived KEK to the chosen algorithm.
The algorithm ID identifies unequivocally the algorithm, the parameters for its instantiation, and the length of all artifacts, including the derived key.

## ML-DSA and SLH-DSA hedged variants {#hedged-sec-cons}

This specification makes use of the default "hedged" variants of ML-DSA and SLH-DSA, which mix fresh randomness into the respective signature-generation algorithm's internal hashing step.
This has the advantage of an enhanced side-channel resistance of the signature operations according to  {{FIPS-204}} and {{FIPS-205}}.

## Symmetric Algorithms for SEIPD Packets

This specification mandates support for `AES-256` for two reasons.
First, `AES-KeyWrap` with `AES-256` is already part of the composite KEM construction.
Second, some of the PQ(/T) algorithms target the security level of `AES-256`.

For the same reasons, this specification further recommends the use of `AES-256` if it is supported by all recipient certificates, regardless of what the implementation would otherwise choose based on the recipients' preferences.
This recommendation should be understood as a clear and simple rule for the selection of `AES-256` for encryption.
Implementations may also make more nuanced decisions.

## Key generation

When generating keys, this specification requires component keys to be generated independently, and recommends not to reuse existing keys for any of the components.
Note that reusing a key across different protocols may lead to signature confusion vulnerabilities, that formally classify as signature forgeries. Generally, reusing a key for different purposes may lead to subtle vulnerabilities.

# Additional considerations

## Performance Considerations for SLH-DSA {#performance-considerations}

This specification introduces both ML-DSA + EdDSA as well as SLH-DSA as PQ(/T) signature schemes.

Generally, it can be said that ML-DSA + EdDSA provides a performance in terms of execution time requirements that is close to that of traditional ECC signature schemes.
Regarding the size of signatures and public keys, though, ML-DSA has far greater requirements than traditional schemes like EC-based or even RSA signature schemes.

Implementers may want to offer SLH-DSA for applications where the weaker security assumptions of a hash-based signature scheme are required – namely only the 2nd preimage resistance of a hash function – and thus a potentially higher degree of trust in the long-term security of signatures is achieved.
However, SLH-DSA has performance characteristics in terms of execution time of the signature generation as well as space requirements for the signature that are even greater than those of ML-DSA + EdDSA signature schemes.

Pertaining to the execution time, the particularly costly operation in SLH-DSA is the signature generation.
Depending on the parameter set, it can range from approximately the one hundred fold to more than the two thousand fold of that of ML-DSA-87.
These number are based on the performance measurements published in the NIST submissions for SLH-DSA and ML-DSA.
In order to achieve fast signature generation times, the algorithm SLH-DSA-SHAKE-128f ("f" standing for "fast") should be chosen.
This comes at the expense of a larger signature size.
This choice can be relevant in applications where mass signing occurs or a small latency is required.

In order to minimize the space requirements of an SLH-DSA signature, an algorithm ID with the name ending in "s" for "small" should be chosen.
This comes at the expense of a longer signature generation time.
In particular, SLH-DSA-SHAKE-128s achieves the smallest possible signature size, which is about the double size of an ML-DSA-87 signature.
Where a higher security level than 128 bit is needed, SLH-DSA-SHAKE-256s can be used.

Unlike the signature generation time, the signature verification time of SLH-DSA is not that much larger than that of other PQC schemes.
Based on the performance measurements published in the NIST submissions for SLH-DSA and ML-DSA, the verification time of the SLH-DSA is, for the parameters covered by this specification, larger than that of ML-DSA-87 by a factor ranging from four (for -128s) over nine (for -256s) to twelve (for -128f).

# IANA Considerations

IANA is requested to add the algorithm IDs defined in {{iana-pubkey-algos}} to the existing registry `OpenPGP Public Key Algorithms`.
The field specifications enclosed in brackets for the ML-KEM + ECDH composite algorithms denote fields that are only conditionally contained in the data structure.


{: title="IANA updates for registry 'OpenPGP Public Key Algorithms'" #iana-pubkey-algos}
ID     | Algorithm           | Public Key Format                                                                                                      | Secret Key Format                                                                                                      | Signature Format                                                                                                 | PKESK Format                                                                                                                                                                                           | Reference
---  : | -----               | ---------:                                                                                                             | --------:                                                                                                              | --------:                                                                                                        | -----:                                                                                                                                                                                                 | -----:
30     | ML-DSA-65+Ed25519   | 32 octets Ed25519 public key ({{tab-eddsa-artifacts}}), 1952 octets ML-DSA-65 public key ({{tab-mldsa-artifacts}})     | 32 octets Ed25519 secret key ({{tab-eddsa-artifacts}}), 4032  octets ML-DSA-65 secret ({{tab-mldsa-artifacts}})        | 64 octets Ed25519 signature ({{tab-eddsa-artifacts}}), 3293 octets ML-DSA-65 signature ({{tab-mldsa-artifacts}}) | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
31     | ML-DSA-87+Ed448     | 57 octets Ed448 public key ({{tab-eddsa-artifacts}}),  2592 octets ML-DSA-87 public key ({{tab-mldsa-artifacts}})      | 57 octets Ed448 secret key ({{tab-eddsa-artifacts}}), 4896 octets ML-DSA-87 secret ({{tab-mldsa-artifacts}})           | 114 octets Ed448 signature ({{tab-eddsa-artifacts}}), 4595 octets ML-DSA-87 signature ({{tab-mldsa-artifacts}})  | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
32     | SLH-DSA-SHAKE-128s  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 7856 octets signature ({{slhdsa-artifact-lengths}})                                                              | N/A                                                                                                                                                                                                    | {{slhdsa}}
33     | SLH-DSA-SHAKE-128f  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 17088 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}}
34     | SLH-DSA-SHAKE-256s  | 64 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 128 octets secret key ({{slhdsa-artifact-lengths}})                                                                    | 29792 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}}
35     | ML-KEM-768+X25519   | 32 octets X25519 public key ({{tab-ecdh-cfrg-artifacts}}), 1184 octets ML-KEM-768 public key ({{tab-mlkem-artifacts}}) | 32 octets X25519 secret key ({{tab-ecdh-cfrg-artifacts}}), 2400 octets ML-KEM-768 secret-key ({{tab-mlkem-artifacts}}) | N/A                                                                                                              | 32 octets X25519 ciphertext, 1088 octets ML-KEM-768 ciphertext \[, 1 octet algorithm ID in case of v3 PKESK\], 1 octet length field of value `n`, `n` octets wrapped session key ({{ecc-mlkem-pkesk}}) | {{ecc-mlkem}}
36     | ML-KEM-1024+X448    | 56 octets X448 public key ({{tab-ecdh-cfrg-artifacts}}), 1568  octets ML-KEM-1024 public key ({{tab-mlkem-artifacts}}) | 56 octets X448 secret key ({{tab-ecdh-cfrg-artifacts}}), 3168 octets ML-KEM-1024 secret-key ({{tab-mlkem-artifacts}})  | N/A                                                                                                              | 56 octets X448 ciphertext, 1568 octets ML-KEM-1024 ciphertext \[, 1 octet algorithm ID in case of v3 PKESK\], 1 octet length field of value `n`, `n` octets wrapped session key ({{ecc-mlkem-pkesk}})  | {{ecc-mlkem}}

# Changelog

## draft-wussler-openpgp-pqc-01

- Shifted the algorithm IDs by 4 to align with the crypto-refresh.
- Renamed v5 packets into v6 to align with the crypto-refresh.
- Defined IND-CCA2 security for KDF and key combination.
- Added explicit key generation procedures.
- Changed the key combination KMAC salt.
- Mandated Parameter ID check in SPHINCS+ signature verification.
- Fixed key share size for Kyber-768.
- Added "Preliminaries" section.
- Fixed IANA considerations.

## draft-wussler-openpgp-pqc-02

- Added the ephemeral and public key in the ECC key derivation function.
- Removed public key hash from key combiner.
- Allowed v3 PKESKs and v4 keys with PQ algorithms, limiting them to AES
  symmetric ciphers.
  for encryption with SEIPDv1, in line with the crypto-refresh.

## draft-wussler-openpgp-pqc-03

- Replaced round 3 submission with NIST PQC Draft Standards FIPS 203, 204, 205.
- Added consideration about security level for hashes.

## draft-wussler-openpgp-pqc-04

- Added Johannes Roth as author

## draft-ietf-openpgp-pqc-00

- Renamed draft

## draft-ietf-openpgp-pqc-01

- Mandated `AES-256` as mandatory to implement.
- Added `AES-256` / `AES-128` with `OCB` implicitly to v1/v2 SEIPD preferences of "PQ(/T) certificates".
- Added a recommendation to use `AES-256` when possible.
- Swapped the optional v3 PKESK algorithm identifier with length octet in order to align with X25519 and X448.
- Fixed ML-DSA secret key size.
- Added test vectors.
- Correction and completion of IANA instructions.

## draft-ietf-openpgp-pqc-02
- Removed git rebase artifact.

## draft-ietf-openpgp-pqc-03
- Updated SLH-DSA by removing parametrization and restricting to three SLH-DSA-SHAKE algorithm code points.
- Removed NIST and Brainpool curve hybrids, dropped ECDSA from the current specification.
- Updated KDF as proposed at IETF 119.
- Removed whitespaces from composite algorithm names.
- Explicitly disallowed SED (tag 9) and weak hashes when using PQ algorithms.

## draft-ietf-openpgp-pqc-04
- Fixed ML-DSA signature size.
- Fixed parameters order in PKESK description.
- Fixed missing inputs into KEM combination description.
- Improved parallel encryption guidance.
- Improved SED deprecation decscription.
- Added ML-DSA test vectors.

## draft-ietf-openpgp-pqc-05
- Reworked KEM combiner for the purpose of NIST-compliance.
- Mandated v6 keys for ML-KEM + ECDH algorithms.
- Defined secret key seed format for ML-KEM and ML-DSA.
- Added key generation security considerations.
- Replaced initial public drafts with FIPS 203, 204, 205.

## draft-ietf-openpgp-pqc-06
- Fixed and improved test vectors.

## draft-ietf-openpgp-pqc-07
- Assigned code points 30 - 34 for ML-DSA + EdDSA and SLH-DSA algorithms.
- Aligned KEM combiner with LAMPS.
- Dropped CCA-conversion of X25519/X448 and adjusted security considerations.
- Switched to hedged variant also for SLH-DSA.

## draft-ietf-openpgp-pqc-08
- Assigned code points 35 and 36 for ML-KEM + ECDH algorithms.
- Removed hash binding for ML-DSA + EdDSA and SLH-DSA algorithms.
- Allowed usage of ML-KEM-768 + X25519 with v4 keys
- Aligned KEM combiner to X-Wing and switched to suffix-free encoding of the domain separator

# Contributors

Stephan Ehlen (BSI)<br>
Carl-Daniel Hailfinger (BSI)<br>
Andreas Huelsing (TU Eindhoven)

# Acknowledgments
{:numbered="false"}

Thanks to Daniel Huigens and Evangelos Karatsiolis for the early review and feedback on this document.

--- back

# Test Vectors

To help implementing this specification a set of non-normative examples follow here.

## Sample v6 Ed25519 with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-ed25519}

Here is a Transferable Secret Key consisting of:

- A v6 Ed25519 Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 X25519 Private-Subkey packet
- A v6 subkey binding signature
- A v6 ML-KEM-768+X25519 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `2357faea8775f69acb11183f81b765cc30db7daf2768827babe202a16d07d4aa`.

The first subkey has the fingerprint `fe0f1b20e62a56caacc4d68f32e5a0a3c1e7a69a7d13541fa1761a3933b5b8cf`.

The second subkey has the fingerprint `23eee71a76bc1eab20017a2ba4af492136ec6e6296ed60128b2223273bcb4d2c`.

{: sourcecode-name="v6-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-ed25519}

Here is the corresponding Transferable Public Key for {{test-vector-sec-ed25519}} consisting of:

- A v6 Ed25519 Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 X25519 Public-Subkey packet
- A v6 subkey binding signature
- A v6 ML-KEM-768+X25519 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-ed25519}} and signed by the secret key {{test-vector-sec-ed25519}}:

- A v3 PKESK
- A v1 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `64b5bcf1facc004c9939db330c24bafc5a5d66bee2a4d93ee9c6ca722fa0c09d`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `de2a3622b030e3ec76f8971be2f7866d367780b24b990948460b82885873db45`.

The hex-encoded output of `multiKeyCombine` is `ca6d4f02bc531f16a096c2596eb983e47de08a0462d93072f641cff8bb275719`.

The hex-encoded session key is `766069bccd89f5f196159cac2e489e081d80ba7c54a79f03f7e8fad0fef7c246`.

{: sourcecode-name="v6-eddsa-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-message.asc}
~~~


## Sample v4 Ed25519 with ML-KEM-768+X25519 Data


### Transferable Secret Key {#test-vector-sec-v4-ed25519}

Here is a Transferable Secret Key consisting of:

- A v4 Ed25519 Private-Key packet
- A v4 direct key self-signature
- A User ID packet
- A v4 positive certification self-signature
- A v4 X25519 Private-Subkey packet
- A v4 subkey binding signature
- A v4 ML-KEM-768+X25519 Private-Subkey packet
- A v4 subkey binding signature

The primary key has the fingerprint `bee82527bae0f931a3195628a3687fdca62e4844`.

The first subkey has the fingerprint `3e6a6bd51614ff3810ad2256ada71a07c0afbd7d`.

The second subkey has the fingerprint `3c5e54c7de276f3e308e7da8c5bcde48f991e7c8`.

{: sourcecode-name="v4-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-v4-ed25519}

Here is the corresponding Transferable Public Key for {{test-vector-sec-v4-ed25519}} consisting of:

- A v4 Ed25519 Public-Key packet
- A v4 direct key self-signature
- A User ID packet
- A v4 positive certification self-signature
- A v4 X25519 Public-Subkey packet
- A v4 subkey binding signature
- A v4 ML-KEM-768+X25519 Public-Subkey packet
- A v4 subkey binding signature

{: sourcecode-name="v4-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-v4-ed25519}} and signed by the secret key {{test-vector-sec-v4-ed25519}}:

- A v3 PKESK
- A v1 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `7c0a891f086a52eaf4ba21084c7ef13aae3b9507da54dd256861fc28525aecc6`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `9083fc83286b1676dd95750332b44040022761a1cb205cf0f919cad86e9fee53`.

The hex-encoded output of `multiKeyCombine` is `8132887889f1f8e998ee9458b7fb9185aaa8ffbb8593002d6f6550e0b1e27771`.

The hex-encoded session key is `e23f844c92acffb60feacf70c98b826d8c5dc9af1e0a894a01865877def9f55c`.

{: sourcecode-name="v4-eddsa-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-message.asc}
~~~


## Sample ML-DSA-65+Ed25519 with ML-KEM-768+X25519 Data


### Transferable Secret Key {#test-vector-sec-mldsa65}

Here is a Transferable Secret Key consisting of:

- A v6 ML-DSA-65+Ed25519 Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `42120bfb467bf42c8a3eecb7fd38a8ba426ae95d916f9e77c3fd3f3955e1627d`.

The subkey has the fingerprint `8333c14b27fd556d29b18141811531452dd88c23a1c09e92561521014c1cc460`.

{: sourcecode-name="v6-mldsa-65-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-mldsa65}

Here is the corresponding Transferable Public Key for {{test-vector-sec-mldsa65}} consisting of:

- A v6 ML-DSA-65+Ed25519 Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-mldsa-65-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-mldsa65}} and signed by the secret key {{test-vector-sec-mldsa65}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `dd2624e09d324b23a23da8940c606b7e16080dcc8770cbe0956d4fbe89bdf6c1`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `780a7139851473d02ce4d970bc5f4fe92f0c8fdf51e52b435c842f534adb8b6d`.

The hex-encoded output of `multiKeyCombine` is `d988239e4524f0defc4396e79491782b4ca6801045184d69a48288ba0695a25a`.

The hex-encoded session key is `e3b55fda0b17b52825146f3c547c60b5aa7cfdaf0fc3b573745f5553632f9526`.

{: sourcecode-name="v6-mldsa-65-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-message.asc}
~~~

### Detached signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-mldsa65}}:

- A v6 signature packet

{: sourcecode-name="v6-mldsa-65-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-signature.asc}
~~~


## Sample ML-DSA-87+Ed448 with ML-KEM-1024+X448 Data

### Transferable Secret Key {#test-vector-sec-mldsa87}

Here is a Transferable Secret Key consisting of:

- A v6 ML-DSA-87+Ed448 Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `4141f9deb6ee8c3f8484c3e0d0f41796da5c6b8e6994145e3a335f557cf544c3`.

The subkey has the fingerprint `8cc1fdaed98c2f3b0601eab83fe96e06a44d234bbe61d9b04c1e81c4f66d2080`.

{: sourcecode-name="v6-mldsa-87-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-mldsa87}

Here is the corresponding Transferable Public Key for {{test-vector-sec-mldsa87}} consisting of:

- A v6 ML-DSA-87+Ed448 Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-mldsa-87-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-mldsa87}} and signed by the secret key {{test-vector-sec-mldsa87}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `595d8d4aeb0351df9ce5a4c687e923e79c869c40ecae2b8270e06f5ff24568c4`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `0a1733584155ba6681501814af1391b86a4e5c36af9d391456012be3e6dc2aed16920b65e71f7df7605d4e77add46408374acf8c8eb89717`.

The hex-encoded output of `multiKeyCombine` is `5834e06ba1f79985bcad6e085b709e50a2fc908e6fa1ba90f2550cc93812ed0c`.

The hex-encoded session key is `b53d7bd20c351ed89af94d091f69ece4ccec3bb9d000387ff71e3d7ba53759b0`.

{: sourcecode-name="v6-mldsa-87-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-message.asc}
~~~

### Detached signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-mldsa87}}:

- A v6 signature packet

{: sourcecode-name="v6-mldsa-87-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-signature.asc}
~~~


## Sample SLH-DSA-128s with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-128s}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-128s Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `e761d4ec762a5f9c35f72b0c8a030c184b903c35459e74b25341b245819ab3fe`.

The subkey has the fingerprint `1090ff914d4fb0a40eb3354aeec8575609f0f72e6ad881f54e94932cd78227f6`.

{: sourcecode-name="v6-slhdsa-128s-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-128s}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-128s}} consisting of:

- A v6 SLH-DSA-128s Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-128s-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-slhdsa-128s}} and signed by the secret key {{test-vector-sec-slhdsa-128s}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `daca96724eaee6a4353554dab8a0fdcc5efec22f7880ab93fcf65b0e833a716c`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `66abbce3af562ad2e95489c2e53c27d98f832240579a468f5a2ca6cfbe10ad7a`.

The hex-encoded output of `multiKeyCombine` is `37348a4e107d3dda99af10f1ce2711a539176e709a1fd8be1068ff2c297facb1`.

The hex-encoded session key is `2c2cc21a9a2f765af36e9e767d6c3aebd81e1b93d6b9bee38fdfa6e679a5409d`.

{: sourcecode-name="v6-slhdsa-128s-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-message.asc}
~~~

### Detached signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-128s}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-128s-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-signature.asc}
~~~


## Sample SLH-DSA-128f with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-128f}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-128f Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `7625d0725493f2a0c38080e3a3928016d73ec056e4cf54b1f93a1da7794e67ad`.

The subkey has the fingerprint `cea501a4831757a33b9fa03973b81656cf2ecac6f705daf1647e1f7190366ca6`.

{: sourcecode-name="v6-slhdsa-128f-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-128f}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-128f}} consisting of:

- A v6 SLH-DSA-128f Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-128f-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-pk.asc}
~~~

### Detached signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-128f}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-128f-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-signature.asc}
~~~

## Sample SLH-DSA-256s with ML-KEM-1024+X448 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-256s}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-256s Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `eb55807530d02e475e5a6f403fec5ff9c60b078395fab4c9a862ec8c82a12a95`.

The subkey has the fingerprint `6e8bbbed8d24472510941bf18639f7f799f86e8d8f3a8f49694e5687885388c1`.

{: sourcecode-name="v6-slhdsa-256s-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-256s}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-256s}} consisting of:

- A v6 SLH-DSA-256s Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-256s-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-pk.asc}
~~~

### Detached signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-256s}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-256s-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-signature.asc}
~~~

