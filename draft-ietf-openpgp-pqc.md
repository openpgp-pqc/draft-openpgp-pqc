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
    email: stavros.kousidis@bsi.bund.de
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

  I-D.ietf-openpgp-crypto-refresh:

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
        ins: R. Davis
        name: Richard Davis
    date: August 2020
    seriesinfo:
      NIST Special Publication 800-56C Rev. 2

  SP800-185:
    target: https://doi.org/10.6028/NIST.SP.800-185
    title: 'SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash'
    author:
      -
        ins: J. Kelsey
        name: John Kelsey
      -
        ins: S. Chang
        name: Shu-jen Chang
      -
        ins: R. Perlner
        name: Ray Perlner
    date: December 2016
    seriesinfo:
      NIST Special Publication 800-185

  SP800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
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
        ins: A. Vassilev
        name: Apostol Vassilev
      -
        ins: R. Davis
        name: Richard Davis
    date: April 2018
    seriesinfo:
      NIST Special Publication 800-56A Rev. 3

  SP800-186:
    target: https://doi.org/10.6028/NIST.SP.800-186
    title: 'Recommendations for Discrete Logarithm-Based Cryptography:  Elliptic Curve Domain Parameters'
    author:
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: A. Regenscheid
        name: Andrew Regenscheid
      -
        ins: K. Randall
        name: Karen Randall
    date: February 2023
    seriesinfo:
      NIST Special Publication 800-186

  FIPS-203:
      target: https://doi.org/10.6028/NIST.FIPS.203.ipd
      title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  FIPS-204:
      target: https://doi.org/10.6028/NIST.FIPS.204.ipd
      title: Module-Lattice-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  FIPS-205:
      target: https://doi.org/10.6028/NIST.FIPS.205.ipd
      title: Stateless Hash-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  GHP18:
    target: https://doi.org/10.1007/978-3-319-76578-5_7
    title: KEM Combiners
    date: 2018
    author:
      -
        ins: F. Giacon
        name: Federico Giacon
      -
        ins: F. Heuer
        name: Felix Heuer
      -
        ins: B. Poettering
        name: Bertram Poettering

  BDPA08:
    target: https://doi.org/10.1007/978-3-540-78967-3_11
    title: On the Indifferentiability of the Sponge Construction
    author:
      -
        ins: G. Bertoni
        name: Guido Bertoni
      -
        ins: J. Daemen
        name: Joan Daemen
      -
        ins: M. Peters
        name: Michael Peters
      -
        ins: G. Assche
        name: Gilles van Assche
    date: 2008

  CS03:
    target: https://doi.org/10.1137/S0097539702403773
    title: Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack
    author:
      -
        ins: R. Cramer
        name: Ronald Cramer
      -
        ins: V. Shoup
        name: Victor Shoup
    date: 2003

--- abstract

This document defines a post-quantum public-key algorithm extension for the OpenPGP protocol.
Given the generally assumed threat of a cryptographically relevant quantum computer, this extension provides a basis for long-term secure OpenPGP signatures and ciphertexts.
Specifically, it defines composite public-key encryption based on ML-KEM (formerly CRYSTALS-Kyber), composite public-key signatures based on ML-DSA (formerly CRYSTALS-Dilithium), both in combination with elliptic curve cryptography, and SLH-DSA-SHAKE (formerly SPHINCS+) as a standalone public key signature scheme.

--- middle

# Introduction

The OpenPGP protocol supports various traditional public-key algorithms based on the factoring or discrete logarithm problem.
As the security of algorithms based on these mathematical problems is endangered by the advent of quantum computers, there is a need to extend OpenPGP by algorithms that remain secure in the presence of quantum computers.

Such cryptographic algorithms are referred to as post-quantum cryptography.
The algorithms defined in this extension were chosen for standardization by the National Institute of Standards and Technology (NIST) in mid 2022 {{NISTIR-8413}} as the result of the NIST Post-Quantum Cryptography Standardization process initiated in 2016 {{NIST-PQC}}.
Namely, these are ML-KEM {{FIPS-203}} as a Key Encapsulation Mechanism (KEM), a KEM being a modern building block for public-key encryption, and ML-DSA {{FIPS-204}} as well as SLH-DSA-SHAKE {{FIPS-205}} as signature schemes.

For the two ML-* schemes, this document follows the conservative strategy to deploy post-quantum in combination with traditional schemes such that the security is retained even if all schemes but one in the combination are broken.
In contrast, the stateless hash-based signature scheme SLH-DSA-SHAKE is considered to be sufficiently well understood with respect to its security assumptions in order to be used standalone.
To this end, this document specifies the following new set: SLH-DSA-SHAKE standalone and the two ML-* as composite with ECC-based KEM and digital signature schemes.
Here, the term "composite" indicates that any data structure or algorithm pertaining to the combination of the two components appears as single data structure or algorithm from the protocol perspective.

The document specifies the conventions for interoperability between compliant OpenPGP implementations that make use of this extension and the newly defined algorithms or algorithm combinations.

## Conventions used in this Document

### Terminology for Multi-Algorithm Schemes

The terminology in this document is oriented towards the definitions in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}.
Specifically, the terms "multi-algorithm", "composite" and "non-composite" are used in correspondence with the definitions therein.
The abbreviation "PQ" is used for post-quantum schemes.
To denote the combination of post-quantum and traditional schemes, the abbreviation "PQ/T" is used.
The short form "PQ(/T)" stands for PQ or PQ/T.

## Post-Quantum Cryptography

This section describes the individual post-quantum cryptographic schemes.
All schemes listed here are believed to provide security in the presence of a cryptographically relevant quantum computer.
However, the mathematical problems on which the two ML-* schemes and SLH-DSA-SHAKE are based, are fundamentally different, and accordingly the level of trust commonly placed in them as well as their performance characteristics vary.

\[Note to the reader: This specification refers to the NIST PQC draft standards FIPS 203, FIPS 204, and FIPS 205 as if they were a final specification.
This is a temporary solution until the final versions of these documents are available.
The goal is to provide a sufficiently precise specification of the algorithms already at the draft stage of this specification, so that it is possible for implementers to create interoperable implementations.
Furthermore, we want to point out that, depending on possible future changes to the draft standards by NIST, this specification may be updated as soon as corresponding information becomes available.\]

### ML-KEM {#mlkem-intro}

ML-KEM [FIPS-203] is based on the hardness of solving the learning-with-errors problem in module lattices (MLWE).
The scheme is believed to provide security against cryptanalytic attacks by classical as well as quantum computers.
This specification defines ML-KEM only in composite combination with ECDH encryption schemes in order to provide a pre-quantum security fallback.

### ML-DSA {#mldsa-intro}

ML-DSA [FIPS-204] is a signature scheme that, like ML-KEM, is based on the hardness of solving the Learning With Errors problem and a variant of the Short Integer Solution problem in module lattices (MLWE and SelfTargetMSIS).
Accordingly, this specification only defines ML-DSA in composite combination with EdDSA signature schemes.

### SLH-DSA-SHAKE

SLH-DSA-SHAKE [FIPS-205] is a stateless hash-based signature scheme.
Its security relies on the hardness of finding preimages for cryptographic hash functions.
This feature is generally considered to be a high security guarantee.
Therefore, this specification defines SLH-DSA-SHAKE as a standalone signature scheme.

In deployments the performance characteristics of SLH-DSA-SHAKE should be taken into account.
We refer to {{performance-considerations}} for a discussion of the performance characteristics of this scheme.

## Elliptic Curve Cryptography

The ECDH encryption is defined here as a KEM.
Curve25519 and Curve448 are defined in [RFC7748] for use in a Diffie-Hellman key agreement scheme and defined in [RFC8032] for use in a digital signature scheme.

## Standalone and Multi-Algorithm Schemes {#multi-algo-schemes}

This section provides a categorization of the new algorithms and their combinations.

### Standalone and Composite Multi-Algorithm Schemes {#composite-multi-alg}

This specification introduces new cryptographic schemes, which can be categorized as follows:

 - PQ/T multi-algorithm public-key encryption, namely a composite combination of ML-KEM with an ECDH KEM,

 - PQ/T multi-algorithm digital signature, namely composite combinations of ML-DSA with EdDSA signature schemes,

 - PQ digital signature, namely SLH-DSA-SHAKE as a standalone cryptographic algorithm.

For each of the composite schemes, this specification mandates that the recipient has to successfully perform the cryptographic algorithms for each of the component schemes used in a cryptographic message, in order for the message to be deciphered and considered as valid.
This means that all component signatures must be verified successfully in order to achieve a successful verification of the composite signature.
In the case of the composite public-key decryption, each of the component KEM decapsulation operations must succeed.

### Non-Composite Algorithm Combinations {#non-composite-multi-alg}

As the OpenPGP protocol [I-D.ietf-openpgp-crypto-refresh] allows for multiple signatures to be applied to a single message, it is also possible to realize non-composite combinations of signatures.
Furthermore, multiple OpenPGP signatures may be combined on the application layer.
These latter two cases realize non-composite combinations of signatures.
{{multiple-signatures}} specifies how implementations should handle the verification of such combinations of signatures.

Furthermore, the OpenPGP protocol also allows for parallel encryption to different keys held by the same recipient.
Accordingly, if the sender makes use of this feature and sends an encrypted message with multiple PKESK packages for different encryption keys held by the same recipient, a non-composite multi-algorithm public-key encryption is realized where the recipient has to decrypt only one of the PKESK packages in order to decrypt the message.
See {{no-pq-t-parallel-encryption}} for restrictions on parallel encryption mandated by this specification.

# Supported Public Key Algorithms

This section specifies the composite ML-KEM + ECDH and ML-DSA + EdDSA schemes as well as the standalone SLH-DSA-SHAKE signature scheme.
All of these schemes are fully specified via their algorithm ID, i.e., they are not parametrized.

## Algorithm Specifications

For encryption, the following composite KEM schemes are specified:

{: title="KEM algorithm specifications" #kem-alg-specs}
ID                    | Algorithm                          | Requirement | Definition
---------------------:| ---------------------------------- | ----------- | --------------------
TBD (105 for testing) | ML-KEM-768 + X25519                | MUST        | {{ecc-mlkem}}
TBD (106 for testing) | ML-KEM-1024 + X448                 | SHOULD      | {{ecc-mlkem}}

For signatures, the following (composite) signature schemes are specified:

{: title="Signature algorithm specifications" #sig-alg-specs}
ID                    | Algorithm                          | Requirement | Definition
---------------------:| ---------------------------------- | ----------- | --------------------
TBD (107 for testing) | ML-DSA-65 + Ed25519                | MUST        | {{ecc-mldsa}}
TBD (108 for testing) | ML-DSA-87 + Ed448                  | SHOULD      | {{ecc-mldsa}}
TBD (109 for testing) | SLH-DSA-SHAKE-128s                 | MAY         | {{slhdsa}}
TBD                   | SLH-DSA-SHAKE-128f                 | MAY         | {{slhdsa}}
TBD                   | SLH-DSA-SHAKE-256s                 | MAY         | {{slhdsa}}

### Experimental Codepoints for Interop Testing

\[ Note: this section to be removed before publication \]

Algorithms indicated as MAY are not assigned a codepoint in the current state of the draft since there are not enough private/experimental code points available to cover all newly introduced public-key algorithm identifiers.

The use of private/experimental codepoints during development are intended to be used in non-released software only, for experimentation and interop testing purposes only.
An OpenPGP implementation MUST NOT produce a formal release using these experimental codepoints.
This draft will not be sent to IANA without every listed algorithm having a non-experimental codepoint.

# Algorithm Combinations

## Composite KEMs

The ML-KEM + ECDH public-key encryption involves both the ML-KEM and an ECDH KEM in an a priori non-separable manner.
This is achieved via KEM combination, i.e. both key encapsulations/decapsulations are performed in parallel, and the resulting key shares are fed into a key combiner to produce a single shared secret for message encryption.

## Parallel Public-Key Encryption {#no-pq-t-parallel-encryption}

As explained in {{non-composite-multi-alg}}, the OpenPGP protocol inherently supports parallel encryption to different keys of the same recipient.
Implementations MUST NOT encrypt a message with a purely traditional public-key encryption key of a recipient if it is encrypted with a PQ/T key of the same recipient.

## Composite Signatures

The ML-DSA + EdDSA signature consists of independent ML-DSA and EdDSA signatures, and an implementation MUST successfully validate both signatures to state that the ML-DSA + EdDSA signature is valid.

## Multiple Signatures {#multiple-signatures}

The OpenPGP message format allows multiple signatures of a message, i.e. the attachment of multiple signature packets.

An implementation MAY sign a message with a traditional key and a PQ(/T) key from the same sender.
This ensures backwards compatibility due to {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5, since a legacy implementation without PQ(/T) support can fall back on the traditional signature.

Newer implementations with PQ(/T) support MAY ignore the traditional signature(s) during validation.

Implementations SHOULD consider the message correctly signed if at least one of the non-ignored signatures validates successfully.

\[Note to the reader: The last requirement, that one valid signature is sufficient to identify a message as correctly signed, is an interpretation of {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5.\]

## ECC requirements

Even though the zero point, also called the point at infinity, may occur as a result of arithmetic operations on points of an elliptic curve, it MUST NOT appear in any ECC data structure defined in this document.

Furthermore, when performing the explicitly listed operations in {{x25519-kem}} or {{x448-kem}} it is REQUIRED to follow the specification and security advisory mandated from the respective elliptic curve specification.

# Composite KEM schemes

## Building Blocks

### ECDH KEMs {#ecc-kem}

In this section we define the encryption, decryption, and data formats for the ECDH component of the composite algorithms.

{{tab-ecdh-cfrg-artifacts}} describes the ECDH-KEM parameters and artifact lengths.
The artifacts in {{tab-ecdh-cfrg-artifacts}} follow the encodings described in [RFC7748].

{: title="Montgomery curves parameters and artifact lengths" #tab-ecdh-cfrg-artifacts}
|                        | X25519                                     | X448                                       |
|------------------------|--------------------------------------------|--------------------------------------------|
| Algorithm ID reference | TBD (105 for testing)                      | TBD (106 for testing)                      |
| Field size             | 32 octets                                  | 56 octets                                  |
| ECDH-KEM               | x25519Kem ({{x25519-kem}})                 | x448Kem ({{x448-kem}})                     |
| ECDH public key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH secret key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH ephemeral         | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH share             | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| Key share              | 32 octets                                  | 64 octets                                  |
| Hash                   | SHA3-256                                   | SHA3-512                                   |

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

 4. Set the output `ecdhKeyShare` to `SHA3-256(X || ecdhCipherText || ecdhPublicKey)`

The operation `x25519Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X25519(r, V)`, where `r` is the `ecdhSecretKey` and `V` is the `ecdhCipherText`

 2. Set the output `ecdhKeyShare` to `SHA3-256(X || ecdhCipherText || ecdhPublicKey)`

#### X448-KEM {#x448-kem}

The encapsulation and decapsulation operations of `x448kem` are described using the function `X448()` and encodings defined in [RFC7748].
The `ecdhSecretKey` is denoted as `r`, the `ecdhPublicKey` as `R`, they are subject to the equation `R = X25519(r, U(P))`.
Here, `U(P)` denotes the u-coordinate of the base point of Curve448.

The operation `x448.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X448(v,U(P))` where `v` is a randomly generated octet string with a length of 56 octets

 2. Compute the shared coordinate `X = X448(v, R)` where `R` is the recipient's public key `ecdhPublicKey`

 3. Set the output `ecdhCipherText` to `V`

 4. Set the output `ecdhKeyShare` to `SHA3-512(X || ecdhCipherText || ecdhPublicKey)`

The operation `x448Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X448(r, V)`, where `r` is the `ecdhSecretKey` and `V` is the `ecdhCipherText`

 2. Set the output `ecdhKeyShare` to `SHA3-512(X || ecdhCipherText || ecdhPublicKey)`

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
TBD (105 for testing)  | ML-KEM-768  | 1184       | 2400       | 1088       | 32
TBD (106 for testing)  | ML-KEM-1024 | 1568       | 3168       | 1568       | 32

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
TBD (105 for testing)                    | ML-KEM-768   | x25519Kem
TBD (106 for testing)                    | ML-KEM-1024  | x448Kem

The ML-KEM + ECDH composite public-key encryption schemes are built according to the following principal design:

 - The ML-KEM encapsulation algorithm is invoked to create an ML-KEM ciphertext together with an ML-KEM symmetric key share.

 - The encapsulation algorithm of an ECDH KEM, namely X25519-KEM or X448-KEM, is invoked to create an ECDH ciphertext together with an ECDH symmetric key share.

 - A Key-Encryption-Key (KEK) is computed as the output of a key combiner that receives as input both of the above created symmetric key shares and the protocol binding information.

 - The session key for content encryption is then wrapped as described in {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The PKESK package's algorithm-specific parts are made up of the ML-KEM ciphertext, the ECDH ciphertext, and the wrapped session key.

### Fixed information {#kem-fixed-info}

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure, justified in {{sec-fixed-info}}, MUST be used to derive a string to use as binding between the KEK and the communication parties.

    //   Input:
    //   algID     - the algorithm ID encoded as octet

    fixedInfo = algID

### Key combiner {#kem-key-combiner}

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure MUST be used to compute the KEK that wraps a session key.
The construction is a one-step key derivation function compliant to {{SP800-56C}} Section 4, based on KMAC256 {{SP800-185}}.
It is given by the following algorithm, which computes the key encryption key `KEK` that is used to wrap, i.e., encrypt, the session key.

    //   multiKeyCombine(ecdhKeyShare, ecdhCipherText,
    //                   mlkemKeyShare, mlkemCipherText,
    //                   fixedInfo, oBits)
    //
    //   Input:
    //   ecdhKeyShare     - the ECDH key share encoded as an octet string
    //   ecdhCipherText   - the ECDH ciphertext encoded as an octet string
    //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
    //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
    //   fixedInfo       - the fixed information octet string
    //   oBits           - the size of the output keying material in bits
    //
    //   Constants:
    //   domSeparation       - the UTF-8 encoding of the string
    //                         "OpenPGPCompositeKeyDerivationFunction"
    //   counter             - the 4 byte value 00 00 00 01
    //   customizationString - the UTF-8 encoding of the string "KDF"

    ecdhData = ecdhKeyShare || ecdhCipherText
    mlkemData = mlkemKeyShare || mlkemCipherText
    encData = counter || ecdhData || mlkemData || fixedInfo

    KEK = KMAC256(domSeparation, encData, oBits, customizationString)
    return KEK

Here, the parameters to KMAC256 appear in the order as specified in {{SP800-186}}, Section 4, i.e., the key `K`, main input data `X`, requested output length `L`, and optional customization string `S` in that order.

Note that the values `ecdhKeyShare` defined in {{ecc-kem}} and `mlkemKeyShare` defined in {{mlkem-ops}} already use the relative ciphertext in the derivation.
The ciphertext is by design included again in the key combiner to provide a robust security proof.

The value of `domSeparation` is the UTF-8 encoding of the string "OpenPGPCompositeKeyDerivationFunction" and MUST be the following octet sequence:

    domSeparation := 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65
                     4B 65 79 44 65 72 69 76 61 74 69 6F 6E 46 75 6E
                     63 74 69 6F 6E

The value of `counter` MUST be set to the following octet sequence:

    counter :=  00 00 00 01

The value of `fixedInfo` MUST be set according to {{kem-fixed-info}}.

The value of `customizationString` is the UTF-8 encoding of the string "KDF" and MUST be set to the following octet sequence:

    customizationString := 4B 44 46

### Key generation procedure {#ecc-mlkem-generation}

The implementation MUST independently generate the ML-KEM and the ECDH component keys.
ML-KEM key generation follows the specification [FIPS-203] and the artifacts are encoded as fixed-length octet strings as defined in {{mlkem-ops}}.
For ECDH this is done following the relative specification in {{RFC7748}}, and encoding the outputs as fixed-length octet strings in the format specified in {{tab-ecdh-cfrg-artifacts}}.

### Encryption procedure {#ecc-mlkem-encryption}

The procedure to perform public-key encryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the recipient's authenticated public-key packet `pkComposite` and `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite`

 3. Extract the `ecdhPublicKey` and `mlkemPublicKey` component from the algorithm specific data encoded in `pkComposite` with the format specified in {{mlkem-ecc-key}}.

 4. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 5. Compute `(ecdhCipherText, ecdhKeyShare) := ECDH-KEM.Encaps(ecdhPublicKey)`

 6. Compute `(mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)`

 7. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 8. Compute `KEK := multiKeyCombine(ecdhKeyShare, ecdhCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, oBits=256)` as defined in {{kem-key-combiner}}

 9. Compute `C := AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}} that includes a 64 bit integrity check

 10. Output the algorithm specific part of the PKESK as `ecdhCipherText || mlkemCipherText (|| symAlgId) || len(C) || C`, where both `symAlgId` and `len(C)` are single octet fields and `symAlgId` denotes the symmetric algorithm ID used and is present only for a v3 PKESK

### Decryption procedure

The procedure to perform public-key decryption with an ML-KEM + ECDH composite scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID and the `encryptedKey`, i.e., the wrapped session key

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `ecdhSecretKey` and `mlkemSecretKey` from the algorithm specific data of the own secret key encoded in the format specified in {{mlkem-ecc-key}}

 5. Instantiate the ECDH-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 6. Parse `ecdhCipherText`, `mlkemCipherText`, and `C` from `encryptedKey` encoded as `ecdhCipherText || mlkemCipherText (|| symAlgId) || len(C) || C` as specified in {{ecc-mlkem-pkesk}}, where `symAlgId` is present only in the case of a v3 PKESK.

 7. Compute `(ecdhKeyShare) := ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey, ecdhPublicKey)`

 8. Compute `(mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 9. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 10. Compute `KEK := multiKeyCombine(ecdhKeyShare, ecdhCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, oBits=256)` as defined in {{kem-key-combiner}}

 11. Compute `sessionKey := AESKeyUnwrap(KEK, C)`  with AES-256 as per {{RFC3394}}, aborting if the 64 bit integrity check fails

 12. Output `sessionKey`

## Packet specifications

### Public-Key Encrypted Session Key Packets (Tag 1) {#ecc-mlkem-pkesk}

The algorithm-specific fields consists of the output of the encryption procedure described in {{ecc-mlkem-encryption}}:

 - A fixed-length octet string representing an ECDH ephemeral public key in the format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the ML-KEM ciphertext, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

 - A one-octet size of the following fields.

 - Only in the case of a v3 PKESK packet: a one-octet symmetric algorithm identifier.

 - The wrapped session key represented as an octet string.

Note that like in the case of the algorithms X25519 and X448 specified in {{I-D.ietf-openpgp-crypto-refresh}}, for the ML-KEM composite schemes, in the case of a v3 PKESK packet, the symmetric algorithm identifier is not encrypted.
Instead, it is placed in plaintext after the `mlkemCipherText` and before the length octet preceding the wrapped session key.
In the case of v3 PKESK packets for ML-KEM composite schemes, the symmetric algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8 or 9).

In the case of a v3 PKESK, a receiving implementation MUST check if the length of the unwrapped symmetric key matches the symmetric algorithm identifier, and abort if this is not the case.

Implementations MUST NOT use Symmetrically Encrypted Data packets (tag 9) to encrypt data protected with the algorithms described in this document.

### Key Material Packets {#mlkem-ecc-key}

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an EC point public key, in the point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM public key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded secret scalar, whose encoding and length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM secret key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

# Composite Signature Schemes

## Building blocks

### EdDSA-Based signatures {#eddsa-signature}

To sign and verify with EdDSA the following operations are defined:

    (eddsaSignature) <- EdDSA.Sign(eddsaSecretKey, dataDigest)

and

    (verified) <- EdDSA.Verify(eddsaPublicKey, eddsaSignature, dataDigest)

The public and secret key, as well as the signature MUST be encoded according to [RFC8032] as fixed-length octet strings.
The following table describes the EdDSA parameters and artifact lengths:

{: title="EdDSA parameters and artifact lengths in octets" #tab-eddsa-artifacts}
Algorithm ID reference | Curve   | Field size | Public key | Secret key | Signature
----------------------:| ------- | ---------- | ---------- | ---------- | ---------
TBD (107 for testing)  | Ed25519 | 32         | 32         | 32         | 64
TBD (108 for testing)  | Ed448   | 57         | 57         | 57         | 114

### ML-DSA signatures {#mldsa-signature}

For ML-DSA signature generation the default hedged version of `ML-DSA.Sign` given in [FIPS-204] is used.
That is, to sign with ML-DSA the following operation is defined:

    (mldsaSignature) <- ML-DSA.Sign(mldsaSecretKey, dataDigest)

For ML-DSA signature verification the algorithm ML-DSA.Verify given in [FIPS-204] is used.
That is, to verify with ML-DSA the following operation is defined:

    (verified) <- ML-DSA.Verify(mldsaPublicKey, dataDigest, mldsaSignature)

ML-DSA has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mldsa-artifacts}}.
All artifacts are encoded as defined in [FIPS-204].

{: title="ML-DSA parameters and artifact lengths in octets" #tab-mldsa-artifacts}
Algorithm ID reference | ML-DSA    | Public key | Secret key | Signature value
----------------------:| --------- | -----------| ---------- | ---------------
TBD (107 for testing)  | ML-DSA-65 | 1952       | 4032       | 3293
TBD (108 for testing)  | ML-DSA-87 | 2592       | 4896       | 4595

## Composite Signature Schemes with ML-DSA {#ecc-mldsa}

### Signature data digest {#mldsa-sig-data-digest}

Signature data (i.e. the data to be signed) is digested prior to signing operations, see {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4.
Composite ML-DSA + EdDSA signatures MUST use the associated hash algorithm as specified in {{tab-mldsa-hash}} for the signature data digest.
Signatures using other hash algorithms MUST be considered invalid.

An implementation supporting a specific ML-DSA + EdDSA algorithm MUST also support the matching hash algorithm.

{: title="Binding between ML-DSA and signature data digest" #tab-mldsa-hash}
Algorithm ID reference | Hash function | Hash function ID reference
----------------------:| ------------- | --------------------------
TBD (107 for testing)  | SHA3-256      | 12
TBD (108 for testing)  | SHA3-512      | 14

### Key generation procedure {#ecc-mldsa-generation}

The implementation MUST independently generate the ML-DSA and the EdDSA component keys.
ML-DSA key generation follows the specification [FIPS-204] and the artifacts are encoded as fixed-length octet strings as defined in {{mldsa-signature}}.
For EdDSA this is done following the relative specification in {{RFC7748}}, and encoding the artifacts as specified in {{eddsa-signature}} as fixed-length octet strings.

### Signature Generation

To sign a message `M` with ML-DSA + EdDSA the following sequence of operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4

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

The composite ML-DSA + EdDSA schemes MUST be used only with v6 signatures, as defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific v6 signature parameters for ML-DSA + EdDSA signatures consists of:

 - A fixed-length octet string representing the EdDSA signature, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

### Key Material Packets

The composite ML-DSA + EdDSA schemes MUST be used only with v6 keys, as defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA public key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific secret key for ML-DSA + EdDSA keys is this series of values:

 - A fixed-length octet string representing the EdDSA secret key, whose length depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

# SLH-DSA-SHAKE

## The SLH-DSA-SHAKE Algorithms {#slhdsa}

The following table lists the group of algorithm code points for the SLH-DSA-SHAKE signature scheme and the corresponding artifact lengths.
This group of algorithms is henceforth referred to as "SLH-DSA-SHAKE code points".

{: title="SLH-DSA-SHAKE algorithm code points and the corresponding artifact lengths in octets." #slhdsa-artifact-lengths}
Algorithm ID reference   |  SLH-DSA-SHAKE public key | SLH-DSA-SHAKE secret key | SLH-DSA-SHAKE signature
----------------------:  |  ------------------ | ------------------ | ------------------
TBD (SLH-DSA-SHAKE-128s) |  32                 | 64                 | 7856
TBD (SLH-DSA-SHAKE-128f) |  32                 | 64                 | 17088
TBD (SLH-DSA-SHAKE-256s) |  64                 | 128                | 29792

### Signature Data Digest {#slhdsa-sig-data-digest}

Signature data (i.e. the data to be signed) is digested prior to signing operations, see {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4.
SLH-DSA-SHAKE signatures MUST use the associated hash algorithm as specified in {{tab-slhdsa-hash}} for the signature data digest.
Signatures using other hash algorithms MUST be considered invalid.

An implementation supporting a specific SLH-DSA-SHAKE algorithm code point MUST also support the matching hash algorithm.

{: title="Binding between SLH-DSA-SHAKE algorithm code points and signature data hash algorithms" #tab-slhdsa-hash}
Algorithm ID reference   |  Hash function | Hash function ID reference
----------------------:  |  ------------- | --------------------------
TBD (SLH-DSA-SHAKE-128s) |  SHA3-256      | 12
TBD (SLH-DSA-SHAKE-128f) |  SHA3-256      | 12
TBD (SLH-DSA-SHAKE-256s) |  SHA3-512      | 14

### Key generation

SLH-DSA-SHAKE key generation is performed via the algorithm `SLH-DSA.KeyGen` as specified in {{FIPS-205}}, and the artifacts are encoded as fixed-length octet strings as defined in {{slhdsa}}.

### Signature Generation

SLH-DSA-SHAKE signature generation is performed via the algorithm `SLH-DSA.Sign` as specified in {{FIPS-205}}.
The variable `opt_rand` is set to `PK.seed`.
See also {{slhdsa-sec-cons}}.

### Signature Verification

SLH-DSA-SHAKE signature verification is performed via the algorithm `SLH-DSA.Verify` as specified in {{FIPS-205}}.

## Packet specifications

###  Signature Packet (Tag 2)

The SLH-DSA-SHAKE algorithms MUST be used only with v6 signatures, as defined in [I-D.ietf-openpgp-crypto-refresh] Section 5.2.3.

The algorithm-specific part of a signature packet for an SLH-DSA-SHAKE algorithm code point consists of:

 - A fixed-length octet string of the SLH-DSA-SHAKE signature value, whose length depends on the algorithm ID in the format specified in {{slhdsa-artifact-lengths}}.

### Key Material Packets

The SLH-DSA-SHAKE algorithms code points MUST be used only with v6 keys, as defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific part of the public key consists of:

 - A fixed-length octet string containing the SLH-DSA-SHAKE public key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

The algorithm-specific part of the secret key consists of:

 - A fixed-length octet string containing the SLH-DSA-SHAKE secret key, whose length depends on the algorithm ID as specified in {{slhdsa-artifact-lengths}}.

# Notes on Algorithms

## Symmetric Algorithms for SEIPD Packets

Implementations MUST implement `AES-256`.
An implementation SHOULD use `AES-256` in the case of a v1 SEIPD packet, or `AES-256` with any available AEAD mode in the case of a v2 SEIPD packet, if all recipients indicate support for it (explicitly or implicitly).

A v4 or v6 certificate that contains a PQ(/T) key SHOULD include `AES-256` in the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket.
A v6 certificate that contains a PQ(/T) key SHOULD include the pair `AES-256` with `OCB` in the "Preferred AEAD Ciphersuites" subpacket.

If `AES-256` is not explicitly in the list of the "Preferred Symmetric Ciphers for v1 SEIPD" subpacket, and if the certificate contains a PQ/T key, it is implicitly at the end of the list.
This is justified since `AES-256` is mandatory to implement.
If `AES-128` is also implicitly added to the list, it is added after `AES-256`.

If the pair `AES-256` with `OCB` is not explicitly in the list of the "Preferred AEAD Ciphersuites" subpacket, and if the certificate contains a PQ/T key, it is implicitly at the end of the list.
This is justified since `AES-256` and `OCB` are mandatory to implement.
If the pair `AES-128` with `OCB` is also implicitly added to the list, it is added after the pair `AES-256` with `OCB`.

## Hash Algorithms for Key Binding Signatures

Subkey binding signatures over algorithms described in this document and primary key binding signatures made by algorithms described in this document MUST NOT be made with `MD5`, `SHA-1`, or `RIPEMD-160`.
A receiving implementation MUST treat such a signature as invalid.

# Migration Considerations

The post-quantum KEM algorithms defined in {{kem-alg-specs}} and the signature algorithms defined in {{sig-alg-specs}} are a set of new public key algorithms that extend the algorithm selection of {{I-D.ietf-openpgp-crypto-refresh}}.
During the transition period, the post-quantum algorithms will not be supported by all clients.
Therefore various migration considerations must be taken into account, in particular backwards compatibility to existing implementations that have not yet been updated to support the post-quantum algorithms.

## Key preference

Implementations SHOULD prefer PQ(/T) keys when multiple options are available.

For instance, if encrypting for a recipient for which both a valid PQ/T and a valid ECC certificate are available, the implementation SHOULD choose the PQ/T certificate.
In case a certificate has both a PQ/T and an ECC encryption-capable valid subkey, the PQ/T subkey SHOULD be preferred.

An implementation MAY sign with both a PQ(/T) and an ECC key using multiple signatures over the same data as described in {{multiple-signatures}}.
Signing only with PQ(/T) key material is not backwards compatible.

Note that the confidentiality of a message is not post-quantum secure when encrypting to multiple recipients if at least one recipient does not support PQ/T encryption schemes.
An implementation SHOULD NOT abort the encryption process in this case to allow for a smooth transition to post-quantum cryptography.

## Key generation strategies

It is RECOMMENDED to generate fresh secrets when generating PQ(/T) keys.
Note that reusing key material from existing ECC keys in PQ(/T) keys does not provide backwards compatibility.

An OpenPGP certificate is composed of a certification-capable primary key and one or more subkeys for signature, encryption, and authentication.
Two migration strategies are recommended:

1. Generate two independent certificates, one for PQ(/T)-capable implementations, and one for legacy implementations.
   Implementations not understanding PQ(/T) certificates can use the legacy certificate, while PQ(/T)-capable implementations will prefer the newer certificate.
   This allows having an older v4 or v6 certificate for compatibility and a v6 PQ(/T) certificate, at a greater complexity in key distribution.

2. Attach PQ(/T) encryption subkeys to an existing traditional OpenPGP certificate.
   In the case of a v6 certificate, also PQ(/T) signature keys may be attached.
   Implementations understanding PQ(/T) will be able to parse and use the subkeys, while PQ(/T)-incapable implementations can gracefully ignore them.
   This simplifies key distribution, as only one certificate needs to be communicated and verified, but leaves the primary key vulnerable to quantum computer attacks.

# Security Considerations

## Security Aspects of Composite Signatures

When multiple signatures are applied to a message, the question of the protocol's resistance against signature stripping attacks naturally arises.
In a signature stripping attack, an adversary removes one or more of the transmitted signatures such that only a subset of the signatures originally applied by the sender remain in the message that reaches the recipient.
This amounts to a downgrade attack that potentially reduces the value of the signature.
It should be noted that the composite signature schemes specified in this draft are not subject to a signature stripping vulnerability.
This is due to the fact that in any OpenPGP signature, the hashed meta data includes the signature algorithm ID, as specified in {{I-D.ietf-openpgp-crypto-refresh}}, Section 5.2.4.
As a consequence, a component signature taken out of the context of a specific composite algorithm is not a valid signature for any message.

Furthermore, it is also not possible to craft a new signature for a message that was signed twice with a composite algorithm by interchanging (i.e., remixing) the component signatures, which would classify as a weak existential forgery.
This is due to the fact that each v6 signatures also includes a random salt at the start of the hashed meta data, as also specified in the aforementioned reference.

## Hashing in ECDH-KEM

Our construction of the ECDH-KEMs, in particular the inclusion of `ecdhCipherText` in the final hashing step in encapsulation and decapsulation that produces the `ecdhKeyShare`, is standard and known as hashed ElGamal key encapsulation, a hashed variant of ElGamal encryption.
It ensures IND-CCA2 security in the random oracle model under some Diffie-Hellman intractability assumptions [CS03].
The additional inclusion of `ecdhPublicKey` follows the security advice in Section 6.1 of {{RFC7748}}.

## Key combiner {#sec-key-combiner}

For the key combination in {{kem-key-combiner}} this specification limits itself to the use of KMAC.
The sponge construction used by KMAC was proven to be indifferentiable from a random oracle {{BDPA08}}.
This means, that in contrast to SHA2, which uses a Merkle-Damgard construction, no HMAC-based construction is required for key combination.
Except for a domain separation it is sufficient to simply process the concatenation of any number of key shares when using a sponge-based construction like KMAC.
The construction using KMAC ensures a standardized domain separation.
In this case, the processed message is then the concatenation of any number of key shares.

More precisely, for a given capacity `c` the indifferentiability proof shows that assuming there are no weaknesses found in the Keccak permutation, an attacker has to make an expected number of `2^(c/2)` calls to the permutation to tell KMAC from a random oracle.
For a random oracle, a difference in only a single bit gives an unrelated, uniformly random output.
Hence, to be able to distinguish a key `K`, derived from shared keys `K1` and `K2` (and ciphertexts `C1` and `C2`) as

    K = KMAC(domainSeparation, counter || K1 || C1 || K2 || C2 || fixedInfo,
    outputBits, customization)

from a random bit string, an adversary has to know (or correctly guess) both key shares `K1` and `K2`, entirely.

The proposed construction in {{kem-key-combiner}} preserves IND-CCA2 of any of its ingredient KEMs, i.e. the newly formed combined KEM is IND-CCA2 secure as long as at least one of the ingredient KEMs is.
Indeed, the above stated indifferentiability from a random oracle qualifies Keccak as a split-key pseudorandom function as defined in {{GHP18}}.
That is, Keccak behaves like a random function if at least one input shared secret is picked uniformly at random.
Our construction can thus be seen as an instantiation of the IND-CCA2 preserving Example 3 in Figure 1 of {{GHP18}}, up to some reordering of input shared secrets and ciphertexts.
In the random oracle setting, the reordering does not influence the arguments in {{GHP18}}.

## Domain separation and binding {#sec-fixed-info}

The `domSeparation` information defined in {{kem-key-combiner}} provides the domain separation for the key combiner construction.
This ensures that the input keying material is used to generate a KEK for a specific purpose or context.

The `fixedInfo` defined in {{kem-fixed-info}} binds the derived KEK to the chosen algorithm and communication parties.
The algorithm ID identifies unequivocally the algorithm, the parameters for its instantiation, and the length of all artifacts, including the derived key.

This is in line with the Recommendation for ECC in section 5.5 of [SP800-56A].
Other fields included in the recommendation are not relevant for the OpenPGP protocol, since the sender is not required to have a key of their own, there are no pre-shared secrets, and all the other parameters are unequivocally defined by the algorithm ID.

Furthermore, we do not require the recipients public key into the key combiner as the public key material is already included in the component key derivation functions.
Given two KEMs which we assume to be multi-user secure, we combine their outputs using a KEM-combiner:

    K = H(K1, C1, K2, C2), C = (C1, C2)

Our aim is to preserve multi-user security.
A common approach to this is to add the public key into the key derivation for K.
However, it turns out that this is not necessary here.
To break security of the combined scheme in the multi-user setting, the adversary has to distinguish a set of challenge keys

  K*_u = H(K1*_u, C1*_u, K2*_u, C2*_u)

for users u in some set from random, also given ciphertexts `C*_u = (C1*_u, C2*_u)`.
For each of these K* it holds that if the adversary never makes a query

    H(K1*_u, C1*_u, K2*_u, C2*_u)

they have a zero advantage over guessing.

The only multi-user advantage that the adversary could gain therefore consists of queries to H that are meaningful for two different users u1 != u2 and their associated public keys.
This is only the case if

    (c1*_u1, c2*_u1) = (c1*_u2, c2*_u2)

as the ciphertext values decide for which challenge the query is meaningful.
This means that a ciphertext collision is needed between challenges.
Assuming that the randomness used in the generation of the two challenges is uncorrelated, this is negligible.

In consequence, the ciphertexts already work sufficiently well as domain-separator.

## SLH-DSA-SHAKE Message Randomizer {#slhdsa-sec-cons}

The specification of SLH-DSA-SHAKE {{FIPS-205}} prescribes an optional non-deterministic message randomizer.
This is not used in this specification, as OpenPGP v6 signatures already provide a salted signature data digest of the appropriate size.

## Binding hashes in signatures with signature algorithms

In order not to extend the attack surface, we bind the hash algorithm used for signature data digestion to the hash algorithm used internally by the signature algorithm.

ML-DSA internally uses a SHAKE256 digest, therefore we require SHA3 in the ML-DSA + EdDSA signature packet, see {{mldsa-sig-data-digest}}.
Note that we bind a NIST security category 2 hash function to a signature algorithm that falls into NIST security category 3.
This does not constitute a security bottleneck: because of the unpredictable random salt that is prepended to the digested data in v6 signatures, the hardness assumption is not collision resistance but second-preimage resistance.

In the case of SLH-DSA-SHAKE the internal hash algorithm varies based on the algorithm ID, see {{slhdsa-sig-data-digest}}.

## Symmetric Algorithms for SEIPD Packets

This specification mandates support for `AES-256` for two reasons.
First, `AES-KeyWrap` with `AES-256` is already part of the composite KEM construction.
Second, some of the PQ(/T) algorithms target the security level of `AES-256`.

For the same reasons, this specification further recommends the use of `AES-256` if it is supported by all recipients, regardless of what the implementation would otherwise choose based on the recipients' preferences.
This recommendation should be understood as a clear and simple rule for the selection of `AES-256` for encryption.
Implementations may also make more nuanced decisions.

# Additional considerations

## Performance Considerations for SLH-DSA-SHAKE {#performance-considerations}

This specification introduces both ML-DSA + EdDSA as well as SLH-DSA-SHAKE as PQ(/T) signature schemes.

Generally, it can be said that ML-DSA + EdDSA provides a performance in terms of execution time requirements that is close to that of traditional ECC signature schemes.
Regarding the size of signatures and public keys, though, ML-DSA has far greater requirements than traditional schemes like EC-based or even RSA signature schemes.

Implementers may want to offer SLH-DSA-SHAKE for applications where the weaker security assumptions of a hash-based signature scheme are required – namely only the 2nd preimage resistance of a hash function – and thus a potentially higher degree of trust in the long-term security of signatures is achieved.
However, SLH-DSA-SHAKE has performance characteristics in terms of execution time of the signature generation as well as space requirements for the signature that are even greater than those of ML-DSA + EdDSA signature schemes.

Pertaining to the execution time, the particularly costly operation in SLH-DSA-SHAKE is the signature generation.
Depending on the parameter set, it can range from approximately the one hundred fold to more than the two thousand fold of that of ML-DSA-87.
These number are based on the performance measurements published in the NIST submissions for SLH-DSA-SHAKE and ML-DSA.
In order to achieve fast signature generation times, the algorithm SLH-DSA-SHAKE-128f ("f" standing for "fast") should be chosen.
This comes at the expense of a larger signature size.
This choice can be relevant in applications where mass signing occurs or a small latency is required.

In order to minimize the space requirements of an SLH-DSA-SHAKE signature, an algorithm ID with the name ending in "s" for "small" should be chosen.
This comes at the expense of a longer signature generation time.
In particular, SLH-DSA-SHAKE-128s achieves the smallest possible signature size, which is about the double size of an ML-DSA-87 signature.
Where a higher security level than 128 bit is needed, SLH-DSA-SHAKE-256s can be used.

Unlike the signature generation time, the signature verification time of SLH-DSA-SHAKE is not that much larger than that of other PQC schemes.
Based on the performance measurements published in the NIST submissions for SLH-DSA-SHAKE and ML-DSA, the verification time of the SLH-DSA-SHAKE is, for the parameters covered by this specification, larger than that of ML-DSA-87 by a factor ranging from four (for -128s) over nine (for -256s) to twelve (for -128f).

# IANA Considerations

IANA is requested to add the algorithm IDs defined in {{iana-pubkey-algos}} to the existing registry `OpenPGP Public Key Algorithms`.
The field specifications enclosed in brackets for the ML-KEM + ECDH composite algorithms denote fields that are only conditionally contained in the data structure.


{: title="IANA updates for registry 'OpenPGP Public Key Algorithms'" #iana-pubkey-algos}
ID     | Algorithm           | Public Key Format                                                                                                      | Secret Key Format                                                                                                      | Signature Format                                                                                                 | PKESK Format                                                                                                                                                                                           | Reference
---  : | -----               | ---------:                                                                                                             | --------:                                                                                                              | --------:                                                                                                        | -----:                                                                                                                                                                                                 | -----:
TBD    | ML-KEM-768 + X25519 | 32 octets X25519 public key ({{tab-ecdh-cfrg-artifacts}}), 1184 octets ML-KEM-768 public key ({{tab-mlkem-artifacts}}) | 32 octets X25519 secret key ({{tab-ecdh-cfrg-artifacts}}), 2400 octets ML-KEM-768 secret-key ({{tab-mlkem-artifacts}}) | N/A                                                                                                              | 32 octets X25519 ciphertext, 1088 octets ML-KEM-768 ciphertext \[, 1 octet algorithm ID in case of v3 PKESK\], 1 octet length field of value `n`, `n` octets wrapped session key ({{ecc-mlkem-pkesk}}) | {{ecc-mlkem}}
TBD    | ML-KEM-1024 + X448  | 56 octets X448 public key ({{tab-ecdh-cfrg-artifacts}}), 1568  octets ML-KEM-1024 public key ({{tab-mlkem-artifacts}}) | 56 octets X448 secret key ({{tab-ecdh-cfrg-artifacts}}), 3168 octets ML-KEM-1024 secret-key ({{tab-mlkem-artifacts}})  | N/A                                                                                                              | 56 octets X448 ciphertext, 1568 octets ML-KEM-1024 ciphertext \[, 1 octet algorithm ID in case of v3 PKESK\], 1 octet length field of value `n`, `n` octets wrapped session key ({{ecc-mlkem-pkesk}})  | {{ecc-mlkem}}
TBD    | ML-DSA-65 + Ed25519 | 32 octets Ed25519 public key ({{tab-eddsa-artifacts}}), 1952 octets ML-DSA-65 public key ({{tab-mldsa-artifacts}})     | 32 octets Ed25519 secret key ({{tab-eddsa-artifacts}}), 4032  octets ML-DSA-65 secret ({{tab-mldsa-artifacts}})        | 64 octets Ed25519 signature ({{tab-eddsa-artifacts}}), 3293 octets ML-DSA-65 signature ({{tab-mldsa-artifacts}}) | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
TBD    | ML-DSA-87 + Ed448   | 57 octets Ed448 public key ({{tab-eddsa-artifacts}}),  2592 octets ML-DSA-87 public key ({{tab-mldsa-artifacts}})      | 57 octets Ed448 secret key ({{tab-eddsa-artifacts}}), 4896 octets ML-DSA-87 secret ({{tab-mldsa-artifacts}})           | 114 octets Ed448 signature ({{tab-eddsa-artifacts}}), 4595 octets ML-DSA-87 signature ({{tab-mldsa-artifacts}})  | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
TBD    | SLH-DSA-SHAKE-128s  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 7856 octets signature ({{slhdsa-artifact-lengths}})                                                              | N/A                                                                                                                                                                                                    | {{slhdsa}}
TBD    | SLH-DSA-SHAKE-128f  | 32 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 64 octets secret key ({{slhdsa-artifact-lengths}})                                                                     | 17088 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}}
TBD    | SLH-DSA-SHAKE-256s  | 64 octets public key ({{slhdsa-artifact-lengths}})                                                                     | 128 octets secret key ({{slhdsa-artifact-lengths}})                                                                    | 29792 octets signature ({{slhdsa-artifact-lengths}})                                                             | N/A                                                                                                                                                                                                    | {{slhdsa}}

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
- Fixed ML-DSA private key size.
- Added test vectors.
- correction and completion of IANA instructions.

## draft-ietf-openpgp-pqc-02
- Removed git rebase artifact.

## draft-ietf-openpgp-pqc-03
- Updated SLH-DSA by removing parametrization and restricting to three SLH-DSA-SHAKE algorithm code points.
- Removed NIST and Brainpool curve hybrids, dropped ECDSA from the current specification.

# Contributors

Stephan Ehlen (BSI)<br>
Carl-Daniel Hailfinger (BSI)<br>
Andreas Huelsing (TU Eindhoven)

--- back

# Test Vectors

To help implementing this specification a set of non-normative examples follow here.
The test vectors are implemented using the Initial Public Draft (IPD) variant of the ML-DSA and ML-KEM schemes.

## Sample v6 PQC Subkey Artifacts

Here is a Private Key consisting of:

- A v6 Ed25519 Private-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-ipd-768 + X25519 Private-Subkey packet
- A v6 subkey binding signature

The primary key has the fingerprint `52343242345254050219ceff286e9c8e479ec88757f95354388984a02d7d0b59`.

The subkey has the fingerprint `263e34b69938e753dc67ca8ee37652795135e0e16e48887103c11d7307df40ed`.

{: sourcecode-name="v6-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-sk.asc}
~~~

Here is the corresponding Public Key consisting of:

- A v6 Ed25519 Public-Key packet
- A v6 direct key self-signature
- A User ID packet
- A v6 positive certification self-signature
- A v6 ML-KEM-ipd-768 + X25519 Public-Subkey packet
- A v6 subkey binding signature

{: sourcecode-name="v6-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-pk.asc}
~~~

Here is an unsigned message "Testing\n" encrypted to this key:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded KMAC `ecdhKeyShare` input is `4ec7dc0874ce4a3c257fec94f27f2d3c589764a5fbaf27a4b52836df53c86868`.

The hex-encoded KMAC `mlkemKeyShare` input is `9a84cb01b6be6eecd16737fb558b5ca35899403076c7e9f0ee350195e7fbf6c4`.

The hex-encoded KMAC256 output is `15a0f1eed1fb2a50a22f21e82dbce13ae91c45e3b76a9d2c61246c354a05f781`.

The hex-encoded session key is `08f49fd5340b026e7ec751d82cea83a4b92d4837e785bfb66af71387f84156d0`.

{: sourcecode-name="v6-eddsa-sample-message.asc"}
~~~ application/pgp-keys
{::include test-vectors/v6-eddsa-sample-message.asc}
~~~

## V4 PQC Subkey Artifacts

Here is a Private Key consisting of:

- A v4 Ed25519 Private-Key packet
- A User ID packet
- A v4 positive certification self-signature
- A v4 ECDH (Curve25519) Private-Subkey packet
- A v4 subkey binding signature
- A v4 ML-KEM-ipd-768 + X25519 Private-Subkey packet
- A v4 subkey binding signature

The primary key has the fingerprint `b2e9b532d55bd6287ec79e17c62adc0ddd1edd73`.

The ECDH subkey has the fingerprint `95bed3c63f295e7b980b6a2b93b3233faf28c9d2`.

The ML-KEM-ipd-768 + X25519 subkey has the fingerprint `bd67d98388813e88bf3490f3e440cfbaffd6f357`.

{: sourcecode-name="v4-eddsa-sample-sk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-sk.asc}
~~~

Here is the corresponding Public Key consisting of:

- A v4 Ed25519 Public-Key packet
- A User ID packet
- A v4 positive certification self-signature
- A v4 ECDH (Curve25519) Public-Subkey packet
- A v4 subkey binding signature
- A v4 ML-KEM-ipd-768 + X25519 Public-Subkey packet
- A v4 subkey binding signature

{: sourcecode-name="v4-eddsa-sample-pk.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-pk.asc}
~~~

Here is an SEIPDv1 unsigned message "Testing\n" encrypted to this key:

- A v3 PKESK
- A v1 SEIPD

The hex-encoded KMAC `ecdhKeyShare` input is `ba6634c5bab5756868dac8282054b0b30916d764e1f15841222392e5545a67c7`.

The hex-encoded KMAC `mlkemKeyShare` input is `a6b263da0e367b39c2d44bf4c3f66015f410ee4fa674ddbba8d50cde2fc4094a`.

The hex-encoded KMAC256 output is `504bc329627af248947117936bee9e87230d327d5c5f5b4db593c4b58b2d0339`.

The hex-encoded session key is `b639d5feaae6c8eabcf04182322d576298193cfa9555d869cf911ffbbc5e52e7`.

{: sourcecode-name="v4-eddsa-sample-message-v1.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-message-v1.asc}
~~~

Here is an SEIPDv2 unsigned message `testing` encrypted to this key:

- A v6 PKESK
- A v2 SEIPD

The hex-encoded KMAC `ecdhKeyShare` input is `50a74bfb94dc7677bc02f278eb4e7d5d2f1b04e34a2b5c7b8da0579f3e1e0825`.

The hex-encoded KMAC `mlkemKeyShare` input is `161911216c93a5b7936f9a8876c446b0767c904c94786bfc79bcc505b45f5075`.

The hex-encoded KMAC256 output is `ee4dacbc4efac509ad5f79640d5963af038baf512d55974c46ac71db6c1ed579`.

The hex-encoded session key is `27e3c564fa7b8adb7ee1cfede3ee2cda79dd8f1a6d029ebeb7f3880c752185f6`.

{: sourcecode-name="v4-eddsa-sample-message-v2.asc"}
~~~ application/pgp-keys
{::include test-vectors/v4-eddsa-sample-message-v2.asc}
~~~

# Acknowledgments
{:numbered="false"}

Thanks to Daniel Huigens and Evangelos Karatsiolis for the early review and feedback on this document.
