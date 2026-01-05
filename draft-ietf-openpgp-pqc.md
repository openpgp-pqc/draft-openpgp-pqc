---
title: "Post-Quantum Cryptography in OpenPGP"
abbrev: "PQC in OpenPGP"
category: std

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

  IANA-OPENPGP:
      target: https://www.iana.org/assignments/openpgp/openpgp.xhtml#openpgp-public-key-algorithms
      title: OpenPGP Public Key Algorithms
      author:
        - org: IANA

informative:

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

  CHHKM:
    target: https://eprint.iacr.org/2025/1397
    title: Starfighters—On the General Applicability of X-Wing
    date: 2025
    seriesinfo: Cryptology {ePrint} Archive, Paper 2025/1397
    author:
      -
        ins: D. Connolly
        name: Deirdre Connolly
      -
        ins: K. Hövelmanns
        name: Kathrin Hövelmanns
      -
        ins: A. Hülsing
        name: Andreas Hülsing
      -
        ins: S. Kousidis
        name: Stavros Kousidis
      -
        ins: M. Meijers
        name: Matthias Meijers

  BCD+24:
    target: https://doi.org/10.62056/a3qj89n4e
    title: X-Wing The Hybrid KEM You've Been Looking For
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

This document defines a post-quantum public key algorithm extension for the OpenPGP protocol, extending [RFC9580].
Given the generally assumed threat of a cryptographically relevant quantum computer, this extension provides a basis for long-term secure OpenPGP signatures and ciphertexts.
Specifically, it defines composite public key encryption based on ML-KEM (formerly CRYSTALS-Kyber), composite public key signatures based on ML-DSA (formerly CRYSTALS-Dilithium), both in combination with elliptic curve cryptography, and SLH-DSA (formerly SPHINCS+) as a standalone public key signature scheme.

--- middle

# Introduction

The OpenPGP protocol [RFC9580] supports various traditional public key algorithms based on the factoring or discrete logarithm problem.
As the security of algorithms based on these mathematical problems is endangered by the advent of quantum computers, there is a need to extend OpenPGP with algorithms that remain secure in the presence of a cryptographically relevant quantum computer (CRQC), i.e., a quantum computer with sufficient capacity to break traditional public key cryptography.

Such cryptographic algorithms are referred to as post-quantum cryptography (PQC).
The algorithms defined in this extension were chosen for standardization by the US National Institute of Standards and Technology (NIST) in mid-2022 {{NISTIR-8413}} as the result of the NIST Post-Quantum Cryptography Standardization process initiated in 2016 {{NIST-PQC}}.
Namely, these are ML-KEM {{FIPS-203}} as a Key Encapsulation Mechanism (KEM), a KEM being a modern building block for public key encryption, and ML-DSA {{FIPS-204}} as well as SLH-DSA {{FIPS-205}} as signature schemes.

For the two ML-* schemes, this document follows the conservative strategy to deploy post-quantum in combination with traditional schemes such that the security is retained even if all schemes but one in the combination are broken.
Such combinations are referred to as multi-algorithm or "post-quantum/traditional" (PQ/T) hybrid algorithms.
In contrast, the stateless hash-based signature scheme SLH-DSA is considered to be sufficiently well understood with respect to its security assumptions in order to be used standalone.
To this end, this document specifies the following new set: SLH-DSA standalone and the two ML-* as composite with ECC-based KEM and digital signature schemes.
Here, the term "composite" indicates that any data structure or algorithm pertaining to the combination of the two components appears as a single data structure or algorithm from the protocol perspective.

This document extends [RFC9580] by adding KEM and signature algorithms specified in {{composite-kem-section}}, {{composite-signature-section}}, and {{slhdsa-section}} and specifies the conventions for interoperability between compliant OpenPGP implementations.

## Conventions used in this Document

{::boilerplate bcp14-tagged}

In wire format descriptions, the operator "`||`" is used to indicate concatenation of groups of octets.

### Terminology for Multi-Algorithm Schemes

The terminology in this document is oriented towards the definitions in {{?RFC9794}}.
Specifically, the terms "multi-algorithm", "composite" and "non-composite" are used in correspondence with the definitions therein.
The abbreviation "PQ" is used for post-quantum schemes.
To denote the combination of post-quantum and traditional schemes, the abbreviation "PQ/T" is used.
The short form "PQ(/T)" stands for PQ or PQ/T.

## Post-Quantum Cryptography

This section describes the individual post-quantum cryptographic schemes.
All schemes listed here are designed to provide security in the presence of a CRQC.
However, the mathematical problems on which the two ML-* schemes and SLH-DSA are based, are fundamentally different, and accordingly the level of trust commonly placed in them as well as their performance characteristics vary.

### ML-KEM {#mlkem-intro}

ML-KEM [FIPS-203] is based on the hardness of solving the Learning with Errors problem in module lattices (MLWE).
The scheme is believed to provide security against cryptanalytic attacks based on classical as well as quantum algorithms.
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
The performance characteristics of this scheme are discussed in {{performance-considerations}}.

## Elliptic Curve Cryptography

ECDH encryption is defined here as a KEM via X25519 and X448 which are defined in [RFC7748].
EdDSA as defined in [RFC8032] is used as the elliptic curve-based digital signature scheme.

## Standalone and Multi-Algorithm Schemes {#multi-algo-schemes}

This section provides a categorization of the new algorithms and their combinations.

### Standalone and Composite Multi-Algorithm Schemes {#composite-multi-alg}

This specification introduces new cryptographic schemes, which can be categorized as follows:

 - PQ/T multi-algorithm public key encryption, namely a composite combination of ML-KEM with ECDH,

 - PQ/T multi-algorithm digital signature, namely composite combinations of ML-DSA with EdDSA,

 - PQ digital signature, namely SLH-DSA as a standalone cryptographic algorithm.

For each of the composite schemes, this specification mandates that the consuming party successfully perform the cryptographic algorithms for each of the component schemes used in a cryptographic message, for the message to be deciphered and considered as valid.
This means that all component signatures must be verified successfully to achieve a successful verification of the composite signature.
In the case of the composite public key decryption, each of the component KEM decapsulation operations must succeed.

### Non-Composite Algorithm Combinations {#non-composite-multi-alg}

As the OpenPGP protocol [RFC9580] allows for multiple signatures to be applied to a single message, it is also possible to realize non-composite combinations of signatures.
Furthermore, multiple OpenPGP signatures may be combined on the application layer.
These latter two cases realize non-composite combinations of signatures.
{{multiple-signatures}} specifies how implementations should handle the verification of such combinations of signatures.

Furthermore, the OpenPGP protocol also allows parallel encryption to different keys by using multiple Public Key Encrypted Session Key (PKESK) packets, thus realizing non-composite multi-algorithm public key encryption.

# Supported Public Key Algorithms

This section specifies the composite ML-KEM + ECDH and ML-DSA + EdDSA schemes as well as the standalone SLH-DSA signature scheme.
All of these schemes are fully specified via their algorithm ID, that is, they are not parametrized.

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


A conformant implementation MUST implement ML-DSA-65+Ed25519 and ML-KEM-768+X25519.
It SHOULD also implement ML-DSA-87+Ed448 and ML-KEM-1024+X448,
but may omit them if targeting a highly constrained environment.
An implementation MAY implement any of the SLH-DSA algorithms.

The specified algorithm IDs offer two security levels for each scheme, for a tradeoff between security and performance.
The SLH-DSA algorithms offer an additional performance tradeoff between signature generation time ("128f" is faster) and signature size ("128s" is smaller) at the lower of the two SLH-DSA security levels.
The larger parameter sets of ML-DSA and ML-KEM (Algorithm IDs 31 and 36) are recommended to support interoperability, but they are not required for compliance.
Implementations targeting highly constrained environments may omit these larger variants.

For SLH-DSA-SHAKE-256, only the "small" variant is offered to contain signature size.
See also {{performance-considerations}} for further considerations about parameter choices.

# Algorithm Combinations

## Composite KEMs {#composite-kem}

The ML-KEM + ECDH public key encryption involves both the ML-KEM and an ECDH KEM in an a priori non-separable manner.
This is achieved via KEM combination, that is, both key encapsulations/decapsulations are performed in parallel, and the resulting key shares are fed into a key combiner to produce a single shared secret for message encryption.

As explained in {{non-composite-multi-alg}}, the OpenPGP protocol inherently supports parallel encryption to different keys.
Note that the confidentiality of a message is not post-quantum secure when encrypting to different keys unless all keys support PQ(/T) encryption schemes.

## Composite Signatures

The ML-DSA + EdDSA signature consists of independent ML-DSA and EdDSA signatures, and an implementation MUST successfully validate both signatures to state that the ML-DSA + EdDSA signature is valid.

## Multiple Signatures {#multiple-signatures}

The OpenPGP message format allows multiple signatures of a message, that is, the attachment of multiple signature packets.

An implementation MAY sign a message with a traditional key and a PQ(/T) key from the same sender.
This ensures backwards compatibility due to {{Section 5.2.5 of RFC9580}}, since a legacy implementation without PQ(/T) support can fall back on the traditional signature.

Newer implementations with PQ(/T) support MAY ignore the traditional signature(s) during validation.

Implementations SHOULD consider the message correctly signed if at least one of the non-ignored signatures validates successfully.
This is consistent with {{Section 5.2.5 of RFC9580}}.

## ECC Requirements

Even though the zero point, also called the point at infinity, may occur as a result of arithmetic operations on points of an elliptic curve, it MUST NOT appear in any ECC data structure defined in this document.
An implementation MAY signal an error if this condition is encountered.

Furthermore, when performing the explicitly listed operations in {{x25519-kem}} or {{x448-kem}} it is REQUIRED to follow the specification and security advisory mandated from the respective elliptic curve specification [RFC7748].

## Key Version Binding

All PQ(/T) asymmetric algorithms are to be used only in v6 (and newer) keys and certificates, with the single exception of ML-KEM-768+X25519 (algorithm ID 35), which is also allowed in v4 encryption-capable subkeys.

# Composite KEM Schemes {#composite-kem-section}

## Building Blocks

### ECDH KEM {#ecc-kem}

In this section, the encryption, decryption, and data formats for the ECDH component of the composite algorithms are defined.

{{tab-ecdh-cfrg-artifacts}} describes the ECDH KEM parameters and artifact lengths.
The artifacts in {{tab-ecdh-cfrg-artifacts}} follow the encodings described in [RFC7748].

{: title="Montgomery curve parameters and artifact lengths" #tab-ecdh-cfrg-artifacts}
|                        | X25519                      | X448                    |
|------------------------|-----------------------------|-------------------------|
| Algorithm ID reference | 35                          | 36                      |
| ECDH KEM               | X25519-KEM ({{x25519-kem}}) | X448-KEM ({{x448-kem}}) |
| ECDH public key        | 32 octets                   | 56 octets               |
| ECDH secret key        | 32 octets                   | 56 octets               |
| ECDH ephemeral         | 32 octets                   | 56 octets               |
| ECDH key share         | 32 octets                   | 56 octets               |

The various procedures to perform the operations of an ECDH KEM are defined in the following subsections.
Specifically, each of these subsections defines the instances of the following operations:

    (ecdhCipherText, ecdhKeyShare) <- ECDH-KEM.Encaps(ecdhPublicKey)

and

    (ecdhKeyShare) <- ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey)

To instantiate `ECDH-KEM`, one must select a parameter set from {{tab-ecdh-cfrg-artifacts}}.

#### X25519-KEM {#x25519-kem}

The encapsulation and decapsulation operations of `X25519-KEM` are described using the function `X25519()` and encodings defined in [RFC7748].
The `ecdhSecretKey` is denoted as `r`, the `ecdhPublicKey` as `R`, they are subject to the equation `R = X25519(r, U(P))`.
Here, `U(P)` denotes the u-coordinate of the base point of Curve25519.

The operation `X25519-KEM.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X25519(v,U(P))` where `v` is a randomly generated octet string with a length of 32 octets

 2. Compute the shared coordinate `X = X25519(v, R)` where `R` is the recipient's public key `ecdhPublicKey`

 3. Set the output `ecdhCipherText` to `V`

 4. Set the output `ecdhKeyShare` to `X`

The operation `X25519-KEM.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X25519(r, V)`, where `r` is the `ecdhSecretKey` and `V` is the `ecdhCipherText`

 2. Set the output `ecdhKeyShare` to `X`

#### X448-KEM {#x448-kem}

The encapsulation and decapsulation operations of `X448-KEM` are described using the function `X448()` and encodings defined in [RFC7748].
The `ecdhSecretKey` is denoted as `r`, the `ecdhPublicKey` as `R`, they are subject to the equation `R = X448(r, U(P))`.
Here, `U(P)` denotes the u-coordinate of the base point of Curve448.

The operation `X448-KEM.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X448(v,U(P))` where `v` is a randomly generated octet string with a length of 56 octets

 2. Compute the shared coordinate `X = X448(v, R)` where `R` is the recipient's public key `ecdhPublicKey`

 3. Set the output `ecdhCipherText` to `V`

 4. Set the output `ecdhKeyShare` to `X`

The operation `X448-KEM.Decaps()` is defined as follows:

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

{: title="ML-KEM parameters and artifact lengths" #tab-mlkem-artifacts}
|                               | ML-KEM-768  | ML-KEM-1024 |
|-------------------------------| ----------- | ----------- |
| Algorithm ID reference        | 35          | 36          |
| Public (encapsulation) key    | 1184 octets | 1568 octets |
| Secret (decapsulation) key    | 64 octets   | 64 octets   |
| Ciphertext                    | 1088 octets | 1568 octets |
| Key share (shared secret key) | 32 octets   | 32 octets   |


To instantiate `ML-KEM`, one must select a parameter set from the column "ML-KEM" of {{tab-mlkem-artifacts}}.

## Composite Encryption Schemes with ML-KEM {#ecc-mlkem}

{{kem-alg-specs}} specifies the following ML-KEM + ECDH composite public key encryption schemes:

{: title="ML-KEM + ECDH composite schemes" #tab-mlkem-ecc-composite}
Algorithm ID reference                   | ML-KEM       | ECDH-KEM
----------------------------------------:| ------------ | ---------
35                                       | ML-KEM-768   | X25519-KEM
36                                       | ML-KEM-1024  | X448-KEM

The ML-KEM + ECDH composite public key encryption schemes are built according to the following principal design:

 - The ML-KEM encapsulation algorithm is invoked to create an ML-KEM ciphertext together with an ML-KEM symmetric key share.

 - The encapsulation algorithm of an ECDH KEM, namely X25519-KEM or X448-KEM, is invoked to create an ECDH ciphertext together with an ECDH symmetric key share.

 - A Key Encryption Key (KEK) is computed as the output of a key combiner that receives as input both of the above created symmetric key shares, the ECDH ciphertext, the ECDH public key, and the protocol binding information.

 - The session key for content encryption, generated as specified in [RFC9580], is then wrapped as described in {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The PKESK packet's algorithm-specific parts are made up of the ML-KEM ciphertext, the ECDH ciphertext, and the wrapped session key.


### Key Combiner {#kem-key-combiner}

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure MUST be used to compute the KEK that wraps a session key.
The construction is a key derivation function compliant to the QSF/X-Wing construction in {{BCD+24}}, the generalization of which is analyzed in {{CHHKM}}.
It is given by the following algorithm, which computes the key encryption key `KEK` that is used to wrap (that is, encrypt) the session key.


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
    //   ecdhPublicKey   - the ECDH public key of the recipient as an
    //                     octet string
    //   algId           - the OpenPGP algorithm ID of the public key
    //                     encryption algorithm

    KEK = SHA3-256(
              mlkemKeyShare || ecdhKeyShare ||
              ecdhCipherText || ecdhPublicKey ||
              algId || domSep || len(domSep)
          )
    return KEK

The value `domSep` is a constant set to the UTF-8 encoding of the string "OpenPGPCompositeKDFv1", that is:

    domSep = 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31

Here `len(domSep)` is the single octet with the value equal to the octet-length of `domSep`, that is, decimal 21.

### Key Generation Procedure {#ecc-mlkem-generation}

The implementation MUST generate the ML-KEM and the ECDH component keys independently.
ML-KEM key generation follows the specification in [FIPS-203], and the artifacts are encoded as fixed-length octet strings whose sizes are listed in {{mlkem-ops}}.
ECDH key generation follows the specification in {{RFC7748}}, and the artifacts are encoded as fixed-length octet strings whose sizes are listed in {{tab-ecdh-cfrg-artifacts}}.

### Encryption Procedure {#ecc-mlkem-encryption}

The procedure to perform public key encryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the recipient's authenticated public key packet `pkComposite` and `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite` and set it as `algId`

 3. Extract the `ecdhPublicKey` and `mlkemPublicKey` component from the algorithm specific data encoded in `pkComposite` with the format specified in {{mlkem-ecc-key}}.

 4. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 5. Compute `(ecdhCipherText, ecdhKeyShare) = ECDH-KEM.Encaps(ecdhPublicKey)`

 6. Compute `(mlkemCipherText, mlkemKeyShare) = ML-KEM.Encaps(mlkemPublicKey)`

 7. Compute `KEK = multiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, algId)` as defined in {{kem-key-combiner}}

 8. Compute `C = AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}} that includes a 64 bit integrity check

 9. Output the algorithm specific part of the PKESK as `ecdhCipherText || mlkemCipherText || len(C, symAlgId) (|| symAlgId) || C`, where both `symAlgId` and `len(C, symAlgId)` are single octet fields, `symAlgId` denotes the symmetric algorithm ID used and is present only for a v3 PKESK, and `len(C, symAlgId)` denotes the combined octet length of the fields specified as the arguments.

### Decryption Procedure

The procedure to perform public key decryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID as `algId` and the wrapped session key as `encryptedKey`

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `ecdhSecretKey` and `mlkemSecretKey` from the algorithm specific data of the own secret key encoded in the format specified in {{mlkem-ecc-key}}

 5. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 6. Parse `ecdhCipherText`, `mlkemCipherText`, and `C` from `encryptedKey` encoded as `ecdhCipherText || mlkemCipherText || len(C, symAlgId) (|| symAlgId) || C` as specified in {{ecc-mlkem-pkesk}}, where `symAlgId` is present only in the case of a v3 PKESK.

 7. Compute `(ecdhKeyShare) = ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey)`

 8. Compute `(mlkemKeyShare) = ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 9. Compute `KEK = multiKeyCombine(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, algId)` as defined in {{kem-key-combiner}}

 10. Compute `sessionKey = AESKeyUnwrap(KEK, C)` with AES-256 as per {{RFC3394}}, aborting if the 64 bit integrity check fails

 11. Output `sessionKey`

## Packet Specifications

### Public Key Encrypted Session Key Packets (Packet Type ID 1) {#ecc-mlkem-pkesk}

The algorithm-specific fields consist of the output of the encryption procedure described in {{ecc-mlkem-encryption}}:

 - A fixed-length octet string representing an ECDH ephemeral public key in the format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the ML-KEM ciphertext, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

 - A one-octet size of the following fields.

 - Only in the case of a v3 PKESK packet: a one-octet symmetric algorithm identifier.

 - The wrapped session key represented as an octet string.

Note that like in the case of the algorithms X25519 and X448 specified in [RFC9580], for the ML-KEM composite schemes, in the case of a v3 PKESK packet, the symmetric algorithm identifier is not encrypted.
Instead, it is placed in plaintext after the `mlkemCipherText` and before the length octet preceding the wrapped session key.
In the case of v3 PKESK packets for ML-KEM composite schemes, the symmetric algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8 or 9).

In the case of a v3 PKESK, a receiving implementation MUST check if the length of the unwrapped symmetric key matches the symmetric algorithm identifier, and abort if this is not the case.

Implementations MUST NOT use the obsolete Symmetrically Encrypted Data packet (Packet Type ID 9) to encrypt data protected with the algorithms described in this document.

### Key Material Packets {#mlkem-ecc-key}

The composite ML-KEM-768 + X25519 (algorithm ID 35) MUST be used only with v4 or v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

The composite ML-KEM-1024 + X448 (algorithm ID 36) MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

#### Public Key Packets (Packet Type IDs 6 and 14)

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an ECC public key, in the point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM public key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

#### Secret Key Packets (Packet Type IDs 5 and 7)

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded ECDH secret key, whose encoding and length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM secret key in seed format, whose length is 64 octets (compare {{tab-mlkem-artifacts}}).
   The seed format is defined in accordance with Section 3.3 of [FIPS-203].
   Namely, the secret key is given by the concatenation of the values of `d` and `z`, generated in steps 1 and 2 of `ML-KEM.KeyGen` [FIPS-203], each of a length of 32 octets.
   Upon parsing the secret key format, or before using the secret key, for the expansion of the key, the function `ML-KEM.KeyGen_internal` [FIPS-203] has to be invoked with the parsed values of `d` and `z` as input.

# Composite Signature Schemes {#composite-signature-section}

## Building Blocks

### EdDSA-Based Signatures {#eddsa-signature}

Throughout this specification EdDSA refers to the PureEdDSA variant defined in [RFC8032].
The context is always empty.

To sign and verify with EdDSA the following operations are defined:

    (eddsaSignature) <- EdDSA.Sign(eddsaSecretKey, dataDigest)

and

    (verified) <- EdDSA.Verify(eddsaPublicKey, dataDigest, eddsaSignature)

The public and secret key, as well as the signature MUST be encoded according to [RFC8032] as fixed-length octet strings.
The following table describes the EdDSA parameters and artifact lengths:

{: title="EdDSA parameters and artifact lengths" #tab-eddsa-artifacts}
|                        | Ed25519   | Ed448      |
|------------------------| --------- | ---------- |
| Algorithm ID reference | 30        | 31         |
| Public key             | 32 octets | 57 octets  |
| Secret key             | 32 octets | 57 octets  |
| Signature              | 64 octets | 114 octets |


### ML-DSA Signatures {#mldsa-signature}

Throughout this specification ML-DSA refers to the default pure and hedged version of ML-DSA defined in [FIPS-204].

ML-DSA signature generation is performed using the default hedged version of the `ML-DSA.Sign` algorithm, as specified in [FIPS-204], with an empty context string `ctx`.
That is, to sign with ML-DSA the following operation is defined:

    (mldsaSignature) <- ML-DSA.Sign(mldsaSecretKey, dataDigest)

ML-DSA signature verification is performed using the `ML-DSA.Verify` algorithm, as specified in [FIPS-204], with an empty context string `ctx`.
That is, to verify with ML-DSA the following operation is defined:

    (verified) <- ML-DSA.Verify(mldsaPublicKey, dataDigest, mldsaSignature)

ML-DSA has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mldsa-artifacts}}.
All artifacts are encoded as defined in [FIPS-204].

{: title="ML-DSA parameters and artifact lengths" #tab-mldsa-artifacts}
|                        | ML-DSA-65   | ML-DSA-87   |
|------------------------| ----------- | ----------- |
| Algorithm ID reference | 30          | 31          |
| Public key             | 1952 octets | 2592 octets |
| Secret (Private) key   | 32 octets   | 32 octets   |
| Signature              | 3309 octets | 4627 octets |


## Composite Signature Schemes with ML-DSA {#ecc-mldsa}

### Key Generation Procedure {#ecc-mldsa-generation}

The implementation MUST generate the ML-DSA and the EdDSA component keys independently.
ML-DSA key generation follows the specification in [FIPS-204], and the artifacts are encoded as fixed-length octet strings whose sizes are listed in {{mldsa-signature}}.
EdDSA key generation follows the specification in {{RFC8032}}, and the artifacts are encoded as fixed-length octet strings whose sizes are listed in {{eddsa-signature}}.

### Signature Generation

To sign a message `M` with ML-DSA + EdDSA the following sequence of operations has to be performed:

 1. Generate `dataDigest` according to {{Section 5.2.4 of RFC9580}}

 2. Create the EdDSA signature over `dataDigest` with `EdDSA.Sign()` from {{eddsa-signature}}

 3. Create the ML-DSA signature over `dataDigest` with `ML-DSA.Sign()` from {{mldsa-signature}}

 4. Encode the EdDSA and ML-DSA signatures according to the packet structure given in {{ecc-mldsa-sig-packet}}

### Signature Verification

To verify an ML-DSA + EdDSA signature the following sequence of operations has to be performed:

 1. Verify the EdDSA signature with `EdDSA.Verify()` from {{eddsa-signature}}

 2. Verify the ML-DSA signature with `ML-DSA.Verify()` from {{mldsa-signature}}

As specified in {{composite-signature-section}} an implementation MUST validate both signatures, that is, EdDSA and ML-DSA, successfully to state that a composite ML-DSA + EdDSA signature is valid.

## Packet Specifications

### Signature Packet (Packet Type ID 2) {#ecc-mldsa-sig-packet}

The composite ML-DSA + EdDSA schemes MUST be used only with v6 signatures, as defined in [RFC9580], or newer versions defined by updates of that document.

The algorithm-specific v6 signature parameters for ML-DSA + EdDSA signatures consist of:

 - A fixed-length octet string representing the EdDSA signature, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

A composite ML-DSA + EdDSA signature MUST use a hash algorithm with a digest size of at least 256 bits for the computation of the message digest.
A verifying implementation MUST reject any composite ML-DSA + EdDSA signature that uses a hash algorithm with a smaller digest size.

### Key Material Packets

The composite ML-DSA + EdDSA schemes MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

#### Public Key Packets (Packet Type IDs 6 and 14)

The algorithm-specific public key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA public key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

#### Secret Key Packets (Packet Type IDs 5 and 7)

The algorithm-specific secret key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA secret key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key in seed format, whose length is 32 octets (compare {{tab-mldsa-artifacts}}).
   The seed format is defined in accordance with Section 3.6.3 of [FIPS-204].
   Namely, the secret key is given by the value `xi` generated in step 1 of `ML-DSA.KeyGen` [FIPS-204].
   Upon parsing the secret key format, or before using the secret key, for the expansion of the key, the function `ML-DSA.KeyGen_internal` [FIPS-204] has to be invoked with the parsed value of `xi` as input.

# SLH-DSA {#slhdsa-section}

Throughout this specification SLH-DSA refers to the default pure and hedged version of SLH-DSA defined in [FIPS-205].

## The SLH-DSA Algorithms {#slhdsa}

The following table lists the group of algorithm code points for the SLH-DSA signature scheme and the corresponding artifact lengths.
This group of algorithms is henceforth referred to as "SLH-DSA code points".

{: title="SLH-DSA code points and the corresponding artifact lengths." #slhdsa-artifact-lengths}
|                        | SLH-DSA-SHAKE-128s | SLH-DSA-SHAKE-128f | SLH-DSA-SHAKE-256s |
|------------------------| ------------------ | ------------------ | -------------------|
| Algorithm ID reference | 32                 | 33                 | 34                 |
| Public key (PK)        | 32 octets          | 32 octets          | 64 octets          |
| Secret key (SK)        | 64 octets          | 64 octets          | 128 octets         |
| Signature              | 7856 octets        | 17088 octets       | 29792 octets       |


### Key Generation

SLH-DSA key generation is performed via the algorithm `slh_keygen` as specified in {{FIPS-205}}, and the artifacts are encoded as fixed-length octet strings whose sizes are listed in {{slhdsa}}.

### Signature Generation

SLH-DSA signature generation is performed using the default hedged version of the `slh_sign` algorithm, as specified in {{FIPS-205}}, with an empty context string `ctx`.

### Signature Verification

SLH-DSA signature verification is performed using the `slh_verify` algorithm, as specified in {{FIPS-205}}, with an empty context string `ctx`.

## Packet Specifications

### Signature Packet (Packet Type ID 2)

The SLH-DSA algorithms MUST be used only with v6 signatures, as defined in {{Section 5.2.3 of RFC9580}}.

The algorithm-specific part of a signature packet for an SLH-DSA code point consists of:

 - A fixed-length octet string of the SLH-DSA signature value, whose length depends on the algorithm ID in the format specified in {{slhdsa-artifact-lengths}}.

An SLH-DSA signature MUST use a hash algorithm with a digest size of at least 256 bits for the computation of the message digest.
A verifying implementation MUST reject any SLH-DSA signature that uses a hash algorithm with a smaller digest size.

### Key Material Packets

The SLH-DSA code points MUST be used only with v6 keys, as defined in [RFC9580], or newer versions defined by updates of that document.

#### Public Key Packets (Packet Type IDs 6 and 14)

The algorithm-specific part of the public key consists of:

 - A fixed-length octet string containing the SLH-DSA public key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

#### Secret Key Packets (Packet Type IDs 5 and 7)

The algorithm-specific part of the secret key consists of:

 - A fixed-length octet string containing the SLH-DSA secret key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

# Notes on Algorithms

## Symmetric Algorithms for SEIPD Packets

Implementations MUST implement `AES-256`.
An implementation SHOULD use `AES-256` in the case of a v1 Symmetrically Encrypted and Integrity Protected Data (SEIPD) packet, or `AES-256` with any available AEAD mode in the case of a v2 SEIPD packet, if all recipient certificates indicate support for it (explicitly or implicitly).
This requirement is not specified as a MUST, because it would render messages not using AES-256 invalid and subject to rejection upon decryption; however, a receiving implementation may not have access to all recipient certificates and therefore cannot reliably enforce such a requirement.

A certificate that contains a PQ(/T) key SHOULD include `AES-256` in the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket and SHOULD include the pair `AES-256` with `OCB` in the "Preferred AEAD Ciphersuites" subpacket to make support for `AES-256` and `AES-256` with `OCB` explicit.

If `AES-256` is not explicitly in the list of the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket, and if the certificate contains a PQ(/T) key, it is implicitly at the end of the list.
This is justified since `AES-256` is mandatory to implement.
If `AES-128` is also implicitly added to the list, it is added after `AES-256`.

If the pair `AES-256` with `OCB` is not explicitly in the list of the "Preferred AEAD Ciphersuites" subpacket, and if the certificate contains a PQ(/T) key, it is implicitly at the end of the list.
This is justified since `AES-256` and `OCB` are mandatory to implement.
If the pair `AES-128` with `OCB` is also implicitly added to the list, it is added after the pair `AES-256` with `OCB`.

## Hash Algorithms for Key Binding Signatures

Subkey binding signatures (Signature Type 0x18) over algorithms described in this document MUST NOT be made with `MD5`, `SHA-1`, or `RIPEMD-160`.
A receiving implementation MUST treat such a signature as invalid.

# Migration Considerations

The post-quantum KEM algorithms defined in {{kem-alg-specs}} and the signature algorithms defined in {{sig-alg-specs}} are a set of new public key algorithms that extend the algorithm selection of [RFC9580].
During the transition period, the post-quantum algorithms will not be supported by all clients.
Therefore, various migration considerations must be taken into account, in particular backwards compatibility to existing implementations that have not yet been updated to support the post-quantum algorithms.

## Encrypting to Traditional and PQ(/T) Keys

During the transition to post-quantum cryptography, an implementation MAY, by default, encrypt messages to both PQ(/T) and traditional keys to avoid disruption to communications, optionally displaying a warning.
As noted in {{composite-kem}}, the confidentiality of a message is not post-quantum secure when using multiple PKESKs unless all of them use PQ(/T) encryption schemes.

## Signing with Traditional and PQ(/T) Keys

The OpenPGP specification [RFC9580] allows signing a message with multiple signatures.
This implies the possibility to sign with both a PQ(/T) and a traditional key as described in {{multiple-signatures}}.
Note that signing only with PQ(/T) key material is not backwards compatible.

## Verifying with Traditional and PQ(/T) Keys

When verifying, an implementation MAY be willing to accept signatures both from PQ(/T) keys and from traditional keys.
A verifier concerned with a cryptographically relevant quantum computer with knowledge of a peer that has a PQ(/T) signing key MAY prefer instead to ignore all traditional signatures from that peer.

## Generating PQ(/T) Keys {#pq-key-generation}

It is RECOMMENDED to generate fresh secrets when generating PQ(/T) keys.
Note that reusing key material from existing ECC keys in PQ(/T) keys does not provide backwards compatibility.

# Security Considerations

## Security Aspects of Composite Signatures

When multiple signatures are applied to a message, the question of the protocol's resistance against signature stripping attacks naturally arises.
In a signature stripping attack, an adversary removes one or more of the signatures such that only a subset of the signatures remain in the message at the point when it is verified.
This amounts to a downgrade attack that potentially reduces the value of the signature.
It should be noted that the composite signature schemes specified in this draft are not subject to a signature stripping vulnerability.
This is due to the fact that in any OpenPGP signature, the hashed metadata includes the signature algorithm ID, as specified in {{Section 5.2.4 of RFC9580}}.
As a consequence, a component signature taken out of the context of a specific composite algorithm is not a valid OpenPGP signature for any message.

An attacker cannot generate a fresh valid signature for a message that has already been signed twice with the composite algorithm; being able to do so would violate Strong Unforgeability under Chosen Message Attack (SUF-CMA). Specifically, an attacker might try to construct a new signature by remixing the component parts of two legitimate composite signatures. That is impossible because each v6 signature embeds a random salt at the start of its hashed metadata. The two legitimate signatures use different salts, so their components are not interchangeable and cannot be recombined into a valid signature.

### Preventing Signature Cross-Protocol Attacks

Signature cross-protocol attacks exploit the reuse of signatures across different protocols or contexts, allowing attackers to maliciously repurpose valid signatures in unintended ways.
ML-DSA [FIPS-204], SLH-DSA [FIPS-205], and EdDSA [RFC8032] support an optional context string parameter ctx that can be incorporated into the algorithm's internal message preprocessing step before signing and verification.
This context parameter can in principle contribute to the prevention of cross-protocol attacks.
Nevertheless, this specification defines all these algorithms to use an empty context string which is in accordance with the previous use of EdDSA in OpenPGP, and maximizes interoperability with cryptographic libraries.
In order to reliably prevent cross-protocol attacks, this specification recommends avoiding key-reuse across protocols in {{pq-key-generation}}.

## Key Combiner {#sec-key-combiner}

A central security notion of a key combiner is IND-CCA2-security. It is argued in [BCD+24] that the key combiner specified in {{kem-key-combiner}} is IND-CCA2-secure if ML-KEM is IND-CCA2-secure or the Strong Diffie-Hellman problem in a nominal group holds. Note that Curve25519 and Curve448 qualify as such nominal groups {{ABH+21}}.

Note that the inclusion of the ECC public key in the key combiner also accounts for multi-target attacks against X25519 and X448.

### Domain Separation and Context Binding {#sec-fixed-info}

The `domSep` information defined in {{kem-key-combiner}} provides the domain separation for the key combiner construction.
This ensures that the input keying material is used to generate a KEK for a specific purpose.
Appending the length octet ensures that no collisions can result across different domains, which might be defined in the future.
This is because `domSep || len(domSep)` is guaranteed to result in a suffix-free set of octet strings even if further values should be defined for `domSep`.
The term "suffix-free" applied to a set of words indicates that no word is the suffix of another.
Thus, this property ensures unambiguous parsing of a word from the rear of a string.
Unambiguous parseability, in turn, ensures that no collisions can happen on the space of input strings to the key combiner.

The algorithm ID, passed as the `algID` parameter to `multiKeyCombine`, binds the derived KEK to the chosen algorithm.
The algorithm ID identifies unequivocally the algorithm, the parameters for its instantiation, and the length of all artifacts, including the derived key.

## ML-DSA and SLH-DSA Hedged Variants {#hedged-sec-cons}

This specification makes use of the default "hedged" variants of ML-DSA and SLH-DSA, which mix fresh randomness into the respective signature-generation algorithm's internal hashing step.
This has the advantage of an enhanced side-channel resistance of the signature operations according to {{FIPS-204}} and {{FIPS-205}}.

## Minimum Digest Size for PQ(/T) Signatures

This specification requires that all PQ(/T) signatures defined in this document are made on message digests computed with a hash algorithm with at least 256 bits of digest size.
Since all signature algorithms defined in this document require version 6 (or newer) signature packets, which currently include a leading random salt value in the hashed data, the required property is not collision but (2nd) preimage resistance.
Therefore, a hash algorithm with a digest size of at least 256 bits is sufficient to match the targeted security levels of all PQ(/T) algorithms defined in this document.

## Symmetric Algorithms for SEIPD Packets

This specification mandates support for `AES-256` for two reasons.
First, `AES-KeyWrap` with `AES-256` is already part of the composite KEM construction.
Second, some of the PQ(/T) algorithms target the security level of `AES-256`.

For the same reasons, this specification further recommends the use of `AES-256` if it is supported by all recipient certificates, regardless of what the implementation would otherwise choose based on the recipients' preferences.
This recommendation should be understood as a clear and simple rule for the selection of `AES-256` for encryption.
Implementations may also make more nuanced decisions.

## Key Generation

When generating keys, this specification requires component keys to be generated independently, and recommends not to reuse existing keys for any of the components.
Note that reusing a key across different protocols may lead to signature confusion vulnerabilities, that formally classify as signature forgeries.
Generally, reusing a key for different purposes may lead to subtle vulnerabilities.

## Random Number Generation and Seeding

As mandated by {{Section 13.10 of RFC9580}}, all random data must be generated using a cryptographically secure pseudorandom number generator (CSPRNG).

# Additional Considerations

## Performance Considerations for SLH-DSA {#performance-considerations}

This specification introduces both ML-DSA + EdDSA as well as SLH-DSA as PQ(/T) signature schemes.

Generally, it can be said that ML-DSA + EdDSA provides a performance in terms of execution time requirements that is close to that of traditional ECC signature schemes.
Regarding the size of signatures and public keys, though, ML-DSA has far greater requirements than traditional schemes like ECC-based or even RSA signature schemes.

Implementers may want to offer SLH-DSA for applications where the weaker security assumptions of a hash-based signature scheme are required – namely only the 2nd preimage resistance of a hash function – and thus a potentially higher degree of trust in the long-term security of signatures is achieved.
However, SLH-DSA has performance characteristics in terms of execution time of the signature generation as well as space requirements for the signature that are even greater than those of ML-DSA + EdDSA signature schemes.

Pertaining to the execution time, the particularly costly operation in SLH-DSA is the signature generation.
Depending on the parameter set, it can range from approximately one hundred to more than two thousand times that of ML-DSA-87.
These numbers are based on the performance measurements published in the NIST submissions for SLH-DSA and ML-DSA.
In order to achieve fast signature generation times, the algorithm SLH-DSA-SHAKE-128f ("f" standing for "fast") should be chosen.
This comes at the expense of a larger signature size.
This choice can be relevant in applications where mass signing occurs or a small latency is required.

In order to minimize the space requirements of an SLH-DSA signature, an algorithm ID with the name ending in "s" for "small" should be chosen.
This comes at the expense of a longer signature generation time.
In particular, SLH-DSA-SHAKE-128s achieves the smallest possible signature size, which is about the double size of an ML-DSA-87 signature.
Where a higher security level than 128 bit is needed, SLH-DSA-SHAKE-256s can be used.

Unlike the signature generation time, the signature verification time of SLH-DSA is not that much larger than that of other PQC schemes.
Based on the performance measurements published in the NIST submissions for SLH-DSA and ML-DSA, the verification time of SLH-DSA is, for the parameters covered by this specification, larger than that of ML-DSA-87 by a factor ranging from four (for -128s) over nine (for -256s) to twelve (for -128f).

# IANA Considerations

IANA is requested to add the algorithm IDs defined in {{iana-pubkey-algos}} to the existing registry `OpenPGP Public Key Algorithms` maintained at {{IANA-OPENPGP}}.

{: title="IANA updates for registry 'OpenPGP Public Key Algorithms'" #iana-pubkey-algos}
ID     | Algorithm           | Public Key Format                                                                                                      | Secret Key Format                                                                                                      | Signature Format                                                                                                 | PKESK Format                                                                                                                                                                                           | Reference
---  : | -----               | ---------:                                                                                                             | --------:                                                                                                              | --------:                                                                                                        | -----:                                                                                                                                                                                                 | -----:
TBD(30)     | ML-DSA-65+Ed25519   | 32 octets Ed25519 public key ({{tab-eddsa-artifacts}}), 1952 octets ML-DSA-65 public key ({{tab-mldsa-artifacts}})     | 32 octets Ed25519 secret key ({{tab-eddsa-artifacts}}), 32 octets ML-DSA-65 secret key ({{tab-mldsa-artifacts}})        | 64 octets Ed25519 signature ({{tab-eddsa-artifacts}}), 3309 octets ML-DSA-65 signature ({{tab-mldsa-artifacts}}) | N/A                                                                                                                                                                                                       | {{ecc-mldsa}} of RFC TBD
TBD(31)     | ML-DSA-87+Ed448     | 57 octets Ed448 public key ({{tab-eddsa-artifacts}}),  2592 octets ML-DSA-87 public key ({{tab-mldsa-artifacts}})      | 57 octets Ed448 secret key ({{tab-eddsa-artifacts}}), 32 octets ML-DSA-87 secret key ({{tab-mldsa-artifacts}})           | 114 octets Ed448 signature ({{tab-eddsa-artifacts}}), 4627 octets ML-DSA-87 signature ({{tab-mldsa-artifacts}})  | N/A                                                                                                                                                                                                      | {{ecc-mldsa}} of RFC TBD
TBD(32)     | SLH-DSA-SHAKE-128s  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 7856 octets signature ({{slhdsa-artifact-lengths}})                                                              | N/A                                                                                                                                                                                                    | {{slhdsa}} of RFC TBD
TBD(33)     | SLH-DSA-SHAKE-128f  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 17088 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}} of RFC TBD
TBD(34)     | SLH-DSA-SHAKE-256s  | 64 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 128 octets secret key ({{slhdsa-artifact-lengths}})                                                                    | 29792 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}} of RFC TBD
TBD(35)     | ML-KEM-768+X25519   | 32 octets X25519 public key ({{tab-ecdh-cfrg-artifacts}}), 1184 octets ML-KEM-768 public key ({{tab-mlkem-artifacts}}) | 32 octets X25519 secret key ({{tab-ecdh-cfrg-artifacts}}), 64 octets ML-KEM-768 secret-key ({{tab-mlkem-artifacts}}) | N/A                                                                                                              | 32 octets X25519 ciphertext, 1088 octets ML-KEM-768 ciphertext, 1 octet remaining length, \[1 octet algorithm ID in case of v3 PKESK,\] `n` octets wrapped session key ({{ecc-mlkem-pkesk}})             | {{ecc-mlkem}} of RFC TBD
TBD(36)     | ML-KEM-1024+X448    | 56 octets X448 public key ({{tab-ecdh-cfrg-artifacts}}), 1568  octets ML-KEM-1024 public key ({{tab-mlkem-artifacts}}) | 56 octets X448 secret key ({{tab-ecdh-cfrg-artifacts}}), 64 octets ML-KEM-1024 secret-key ({{tab-mlkem-artifacts}})  | N/A                                                                                                              | 56 octets X448 ciphertext, 1568 octets ML-KEM-1024 ciphertext, 1 octet remaining length, \[1 octet algorithm ID in case of v3 PKESK,\] `n` octets wrapped session key ({{ecc-mlkem-pkesk}})              | {{ecc-mlkem}} of RFC TBD

IANA is asked to add the following note to this registry:

> The field specifications enclosed in square brackets for PKESK Format represent fields that may or may not be present, depending on the PKESK version.

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
- Explicitly disallowed SED (Packet Type ID 9) and weak hashes when using PQ algorithms.

## draft-ietf-openpgp-pqc-04
- Fixed ML-DSA signature size.
- Fixed parameters order in PKESK description.
- Fixed missing inputs into KEM combination description.
- Improved parallel encryption guidance.
- Improved SED deprecation description.
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
- Allowed usage of ML-KEM-768 + X25519 with v4 keys.
- Aligned KEM combiner to X-Wing and switched to suffix-free encoding of the domain separator.

## draft-ietf-openpgp-pqc-09
- Removed subkey semantics related guidance.
- Updated test vectors.
- Added non-normative algorithm explanation.

## draft-ietf-openpgp-pqc-10
- Specified minimum requirements for signature message digest sizes.
- Added security considerations for signature message digest sizes.

## draft-ietf-openpgp-pqc-11
- Editorial changes and fixes of inconsistencies.

## draft-ietf-openpgp-pqc-12
- Moved from informational to standards-track.

## draft-ietf-openpgp-pqc-13
- Addressed various editorial comments from AD review.
- Added text about signature verification to the migration considerations section.
- Added text about preventing signature cross-protocol attacks to the security considerations section.

## draft-ietf-openpgp-pqc-14
- Fixed a broken reference.
- Updated KEM combiner references.

## draft-ietf-openpgp-pqc-15
- Addressed various editorial comments from IESG reviews.

## draft-ietf-openpgp-pqc-16
- Addressed more editorial comments from IESG reviews.

# Contributors

Stephan Ehlen (BSI)<br>
Carl-Daniel Hailfinger (BSI)<br>
Andreas Huelsing (TU Eindhoven)

# Acknowledgments
{:numbered="false"}

Thanks to Daniel Kahn Gillmor, Justus Winter, Daniel Huigens, Evangelos Karatsiolis, and early implementers of the draft for their reviews and feedback on this document.

--- back

# Test Vectors

To help with implementing this specification a set of non-normative examples follow here.

## Sample v6 Ed25519 with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-ed25519}

Here is a Transferable Secret Key consisting of:

- A v6 Ed25519 Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947`.

The subkey has the fingerprint `dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d`.

{: sourcecode-name="v6-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-ed25519}

Here is the corresponding Transferable Public Key for {{test-vector-sec-ed25519}} consisting of:

- A v6 Ed25519 Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-ed25519}} and signed by the secret key {{test-vector-sec-ed25519}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932`.

The hex-encoded output of `multiKeyCombine` is `5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590`.

The hex-encoded session key is `94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435`.

{: sourcecode-name="v6-eddsa-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-message.asc}
~~~


## Sample v4 Ed25519 with ML-KEM-768+X25519 Data


### Transferable Secret Key {#test-vector-sec-v4-ed25519}

Here is a Transferable Secret Key consisting of:

- A v4 Ed25519 Private Key packet
- A User ID packet
- A v4 positive certification self-signature
- A v4 ML-KEM-768+X25519 Private Subkey packet
- A v4 subkey binding signature

The primary key has the fingerprint `342e5db2de345215cb2c944f7102ffed3b9cf12d`.

The subkey has the fingerprint `e51dbfea51936988b5428fffa4f95f985ed61a51`.

{: sourcecode-name="v4-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-v4-ed25519}

Here is the corresponding Transferable Public Key for {{test-vector-sec-v4-ed25519}} consisting of:

- A v4 Ed25519 Public Key packet
- A User ID packet
- A v4 positive certification self-signature
- A v4 ML-KEM-768+X25519 Public Subkey packet
- A v4 subkey binding signature

{: sourcecode-name="v4-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-pk.asc}
~~~

### Encrypted and Signed SEIPD v1 Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-v4-ed25519}} and signed by the secret key {{test-vector-sec-v4-ed25519}}:

- A v3 PKESK
- A v1 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e`.

The hex-encoded output of `multiKeyCombine` is `c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f`.

The hex-encoded session key is `b4dc7197e1519822ca689da484643edf272934d98ae1974b5d88317a7a6a3c4f`.

{: sourcecode-name="v4-eddsa-sample-message-v1.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-message-v1.asc}
~~~

### Encrypted and Signed SEIPD v2 Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-v4-ed25519}} and signed by the secret key {{test-vector-sec-v4-ed25519}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `16a22adbeced91ada60b5561611748edd2fedc51e0770f86d7394870062e7322`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `5ac67eab192f25ac99d87543e6fcd3a4769cb02c9d1afdc79354c2baa2289e29`.

The hex-encoded output of `multiKeyCombine` is `5c5652a690b55d1e9545fbd722f838cd8ff4d3657af5a9026d02f3185ca74993`.

The hex-encoded session key is `160867d96032b640208c1c92174d0270bb89189d72320711acd221bbea2a26b6`.

{: sourcecode-name="v4-eddsa-sample-message-v2.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-message-v2.asc}
~~~



## Sample ML-DSA-65+Ed25519 with ML-KEM-768+X25519 Data


### Transferable Secret Key {#test-vector-sec-mldsa65}

Here is a Transferable Secret Key consisting of:

- A v6 ML-DSA-65+Ed25519 Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f`.

The subkey has the fingerprint `7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4`.

{: sourcecode-name="v6-mldsa-65-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-mldsa65}

Here is the corresponding Transferable Public Key for {{test-vector-sec-mldsa65}} consisting of:

- A v6 ML-DSA-65+Ed25519 Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-mldsa-65-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-mldsa65}} and signed by the secret key {{test-vector-sec-mldsa65}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `0987fe72ad5ea58e73344f9a2a543f4131d9fdb7cf07474f501430a20f705b4d`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `88f3e9a8de1917127b4b758f6e83bd4ce00faaae01bd8b6e412a43a710b26012`.

The hex-encoded output of `multiKeyCombine` is `a4904982f7caa9c9de690afd772d8bfe027a1ad6a5bbda00db68963fe303ae8e`.

The hex-encoded session key is `adee68618b302d4bfd7ae3d432bc63a1c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a`.

{: sourcecode-name="v6-mldsa-65-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-message.asc}
~~~

### Detached Signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-mldsa65}}:

- A v6 signature packet

{: sourcecode-name="v6-mldsa-65-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-65-sample-signature.asc}
~~~


## Sample ML-DSA-87+Ed448 with ML-KEM-1024+X448 Data

### Transferable Secret Key {#test-vector-sec-mldsa87}

Here is a Transferable Secret Key consisting of:

- A v6 ML-DSA-87+Ed448 Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20`.

The subkey has the fingerprint `65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f`.

{: sourcecode-name="v6-mldsa-87-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-mldsa87}

Here is the corresponding Transferable Public Key for {{test-vector-sec-mldsa87}} consisting of:

- A v6 ML-DSA-87+Ed448 Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-mldsa-87-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-mldsa87}} and signed by the secret key {{test-vector-sec-mldsa87}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `f18f161e617b8ce5968f109aadea1e7e1511d10165768d36127ba913c00637d2`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `732860c8114ae84a964664b1f607785d11bc7d24d5324510adad89bd52db7ee0df9982ad0d1669bdd05556330c86f2dae9e2edea42e05bc5`.

The hex-encoded output of `multiKeyCombine` is `ef1e32906f67d39bc800d90cabb0033c77ca6dce8ffca3e96d9c7348e2e8c16e`.

The hex-encoded session key is `0588ce40b038aac353d1cf8c67a674b412985105794821013ef154f786c4d89d`.

{: sourcecode-name="v6-mldsa-87-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-message.asc}
~~~

### Detached Signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-mldsa87}}:

- A v6 signature packet

{: sourcecode-name="v6-mldsa-87-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-mldsa-87-sample-signature.asc}
~~~


## Sample SLH-DSA-SHAKE-128s with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-128s}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-128s Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92`.

The subkey has the fingerprint `3e8745a4bb488779e0f32480fa23f8d0bfd8c2f49d7f74e957e1c2ffc2ef4bfc`.

{: sourcecode-name="v6-slhdsa-128s-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-128s}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-128s}} consisting of:

- A v6 SLH-DSA-128s Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-128s-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-pk.asc}
~~~

### Encrypted and Signed Message

Here is a signed message "Testing\n" encrypted to the certificate {{test-vector-pub-slhdsa-128s}} and signed by the secret key {{test-vector-sec-slhdsa-128s}}:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is `5dc60150f5f965ddc8014b6aa2ecae1831467e98fa315422f238984d6421a22e`.

The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is `9dbd0f9bde7fef09817146e53a0b5ce7d27e79612670968fa0025422c578ab55`.

The hex-encoded output of `multiKeyCombine` is `ae8ab57801911c04c7b4c2a2f665cf8d8a8188f948c2a65e39c292d9b1d86e32`.

The hex-encoded session key is `e87567cad8fee5738f92090feed009d8af95437fa664f94da98776d966bbbc52`.

{: sourcecode-name="v6-slhdsa-128s-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-message.asc}
~~~

### Detached Signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-128s}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-128s-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128s-sample-signature.asc}
~~~


## Sample SLH-DSA-SHAKE-128f with ML-KEM-768+X25519 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-128f}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-128f Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `d54e0307021169f7b88beb2b76e3aad0e114be1a8f982d74dba9ca51d03537f4`.

The subkey has the fingerprint `d8875664256c382dd7f3a5ce05021088922811f5d0b1a1f8c7769944a51b7002`.

{: sourcecode-name="v6-slhdsa-128f-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-128f}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-128f}} consisting of:

- A v6 SLH-DSA-128f Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-768+X25519 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-128f-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-pk.asc}
~~~

### Detached Signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-128f}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-128f-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-128f-sample-signature.asc}
~~~

## Sample SLH-DSA-SHAKE-256s with ML-KEM-1024+X448 Data

### Transferable Secret Key {#test-vector-sec-slhdsa-256s}

Here is a Transferable Secret Key consisting of:

- A v6 SLH-DSA-256s Private Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Private Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `72fff84863aeba67f0d1d7691173247dd427533b9d7ee76011c6f77f2ce9fa7a`.

The subkey has the fingerprint `570a5bbab93169876a8240da35a1ada7ba8a640aabe3ab467c797214844df15f`.

{: sourcecode-name="v6-slhdsa-256s-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-sk.asc}
~~~

### Transferable Public Key {#test-vector-pub-slhdsa-256s}

Here is the corresponding Transferable Public Key for {{test-vector-sec-slhdsa-256s}} consisting of:

- A v6 SLH-DSA-256s Public Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-1024+X448 Public Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-slhdsa-256s-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-pk.asc}
~~~

### Detached Signature

Here is a detached signature for the message "Testing\n" made by the secret key {{test-vector-sec-slhdsa-256s}}:

- A v6 signature packet

{: sourcecode-name="v6-slhdsa-256s-sample-signature.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-slhdsa-256s-sample-signature.asc}
~~~

