---
title: "Post-Quantum Cryptography in OpenPGP"
abbrev: "PQC in OpenPGP"
category: info

docname: draft-wussler-openpgp-pqc-latest
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

  RFC8126:

  I-D.ietf-openpgp-crypto-refresh:

informative:

  RFC5639:

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

  SEC1:
    target: https://secg.org/sec1-v2.pdf
    title: "Standards for Efficient Cryptography 1 (SEC 1)"
    author:
      - org: Standards for Efficient Cryptography Group
    date: May 2009

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

  draft-driscoll-pqt-hybrid-terminology:
    target: https://datatracker.ietf.org/doc/html/draft-driscoll-pqt-hybrid-terminology
    title: Terminology for Post-Quantum Traditional Hybrid Schemes
    author:
      -
        ins: F. Driscoll
        name: Florence Driscoll
    date: March 2023

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

This document defines a post-quantum public-key algorithm extension for the
OpenPGP protocol. Given the generally assumed threat of a cryptographically
relevant quantum computer, this extension provides a basis for long-term secure
OpenPGP signatures and ciphertexts. Specifically, it defines composite
public-key encryption based on ML-KEM (formerly CRYSTALS-Kyber), composite
public-key signatures based on ML-DSA (formerly CRYSTALS-Dilithium), both in
combination with elliptic curve cryptography, and SLH-DSA (formerly SPHINCS+)
as a standalone public key signature scheme.

--- middle

# Introduction

The OpenPGP protocol supports various traditional public-key algorithms based
on the factoring or discrete logarithm problem. As the security of algorithms
based on these mathematical problems is endangered by the advent of quantum
computers, there is a need to extend OpenPGP by algorithms that remain secure
in the presence of quantum computers.

Such cryptographic algorithms are referred to as post-quantum cryptography.
The algorithms defined in this extension were chosen for standardization by the
National Institute of Standards and Technology (NIST) in mid 2022
{{NISTIR-8413}} as the result of the NIST Post-Quantum Cryptography
Standardization process initiated in 2016 {{NIST-PQC}}. Namely, these are
ML-KEM (formerly CRYSTALS-Kyber) as a Key Encapsulation Mechanism (KEM), a KEM
being a modern building block for public-key encryption, and ML-DSA (formerly
CRYSTALS-Dilithium) as well as SLH-DSA (formerly SPHINCS+) as signature
schemes.

For the two ML-* schemes, this document follows the conservative strategy to
deploy post-quantum in combination with traditional schemes such that the
security is retained even if all schemes but one in the combination are broken.
In contrast, the stateless hash-based signature scheme SLH-DSA is considered to
be sufficiently well understood with respect to its security assumptions in
order to be used standalone. To this end, this document specifies the following
new set: SLH-DSA standalone and ML-* as composite with ECC-based KEM and
digital signature schemes. Here, the term "composite" indicates that any data
structure or algorithm pertaining to the combination of the two components
appears as single data structure or algorithm from the protocol perspective.

The document specifies the conventions for interoperability between compliant
OpenPGP implementations that make use of this extension and the newly defined
algorithms or algorithm combinations.

## Conventions used in this Document

### Terminology for Multi-Algorithm Schemes

The terminology in this document is oriented towards the definitions in
[draft-driscoll-pqt-hybrid-terminology]. Specifically, the terms
"multi-algorithm", "composite" and "non-composite" are used in correspondence
with the definitions therein. The abbreviation "PQ" is used for post-quantum
schemes. To denote the combination of post-quantum and traditional schemes, the
abbreviation "PQ/T" is used. The short form "PQ(/T)" stands for PQ or PQ/T.

## Post-Quantum Cryptography

This section describes the individual post-quantum cryptographic schemes. All
schemes listed here are believed to provide security in the presence of a
cryptographically relevant quantum computer. However, the mathematical problems
on which the two ML-* schemes and SLH-DSA are based, are fundamentally
different, and accordingly the level of trust commonly placed in them as well
as their performance characteristics vary.

### ML-KEM {#mlkem-intro}

ML-KEM [FIPS-203] is based on the hardness of solving the learning-with-errors
problem in module lattices (MLWE). The scheme is believed to provide security
against cryptanalytic attacks by classical as well as quantum computers. This
specification defines ML-KEM only in composite combination with ECC-based
encryption schemes in order to provide a pre-quantum security fallback.

### ML-DSA {#mldsa-intro}

ML-DSA [FIPS-204] is a signature scheme that, like ML-KEM, is based on the
hardness of solving the Learning With Errors problem and a variant of the Short Integer Solution problem in module lattices (MLWE and SelfTargetMSIS). Accordingly, this
specification only defines ML-DSA in composite combination with ECC-based
signature schemes.

### SLH-DSA

SLH-DSA [FIPS-205] is a stateless hash-based signature scheme. Its security
relies on the hardness of finding preimages for cryptographic hash functions.
This feature is generally considered to be a high security guarantee.
Therefore, this specification defines SLH-DSA as a standalone signature scheme.

In deployments the performance characteristics of SLH-DSA should be taken into
account. We refer to {{performance-considerations}} for a discussion of the
performance characteristics of this scheme.

## Elliptic Curve Cryptography

The ECC-based encryption is defined here as a KEM. This is in contrast to
{{I-D.ietf-openpgp-crypto-refresh}} where the ECC-based encryption is defined
as a public-key encryption scheme.

All elliptic curves for the use in the composite combinations are taken from
{{I-D.ietf-openpgp-crypto-refresh}}. However, as explained in the following, in
the case of Curve25519 encoding changes are applied to the new composite
schemes.

### Curve25519 and Curve448

Curve25519 and Curve448 are defined in [RFC7748] for use in a Diffie-Hellman
key agreement scheme and defined in [RFC8032] for use in a digital signature
scheme. For Curve25519 this specification adapts the encoding of objects as
defined in [RFC7748] in contrast to [I-D.ietf-openpgp-crypto-refresh].

### Generic Prime Curves

For interoperability this extension offers CRYSTALS-* in composite combinations
with the NIST curves P-256, P-384 defined in {{SP800-186}} and the
Brainpool curves brainpoolP256r1, brainpoolP384r1 defined in {{RFC5639}}.


## Standalone and Multi-Algorithm Schemes {#multi-algo-schemes}

This section provides a categorization of the new algorithms and their
combinations.

### Standalone and Composite Multi-Algorithm Schemes {#composite-multi-alg}

This specification introduces new cryptographic schemes, which can be
categorized as follows:

 - PQ/T multi-algorithm public-key encryption, namely a composite combination
   of ML-KEM with an ECC-based KEM,

 - PQ/T multi-algorithm digital signature, namely composite combinations of
   ML-DSA with ECC-based signature schemes,

 - PQ digital signature, namely SLH-DSA as a standalone cryptographic
   algorithm.

For each of the composite schemes, this specification mandates that the
recipient has to successfully perform the cryptographic algorithms for each of
the component schemes used in a cryptrographic message, in order for the
message to be deciphered and considered as valid. This means that all component
signatures must be verified successfully in order to achieve a successful
verification of the composite signature. In the case of the composite
public-key decryption, each of the component KEM decapsulation operations must
succeed.

### Non-Composite Algorithm Combinations {#non-composite-multi-alg}

As the OpenPGP protocol [I-D.ietf-openpgp-crypto-refresh] allows for multiple
signatures to be applied to a single message, it is also possible to realize
non-composite combinations of signatures. Furthermore, multiple OpenPGP
signatures may be combined on the application layer. These latter two cases
realize non-composite combinations of signatures. {{multiple-signatures}}
specifies how implementations should handle the verification of such
combinations of signatures.

Furthermore, the OpenPGP protocol also allows for parallel encryption to
different keys held by the same recipient. Accordingly, if the sender makes use
of this feature and sends an encrypted message with multiple PKESK packages for
different encryption keys held by the same recipient, a non-composite
multi-algorithm public-key encryption is realized where the recipient has to
decrypt only one of the PKESK packages in order to decrypt the message. See
{{no-pq-t-parallel-encryption}} for restrictions on parallel encryption
mandated by this specification.

# Preliminaries

This section provides some preliminaries for the definitions in the subsequent
sections.

## Elliptic curves

### SEC1 EC Point Wire Format {#sec1-format}

Elliptic curve points of the generic prime curves are encoded using the SEC1
(uncompressed) format as the following octet string:

    B = 04 || X || Y

where `X` and `Y` are coordinates of the elliptic curve point `P = (X, Y)`, and
each coordinate is encoded in the big-endian format and zero-padded to the
adjusted underlying field size. The adjusted underlying field size is the
underlying field size rounded up to the nearest 8-bit boundary, as noted in the
"Field size" column in {{tab-ecdh-nist-artifacts}},
{{tab-ecdh-brainpool-artifacts}}, or {{tab-ecdsa-artifacts}}. This encoding is
compatible with the definition given in [SEC1].

### Measures to Ensure Secure Implementations

In the following measures are described that ensure secure implementations
according to existing best practices and standards defining the operations of
Elliptic Curve Cryptography.

Even though the zero point, also called the point at infinity, may occur as a
result of arithmetic operations on points of an elliptic curve, it MUST NOT
appear in any ECC data structure defined in this document.

Furthermore, when performing the explicitly listed operations in
{{x25519-kem}}, {{x448-kem}} or {{ecdh-kem}} it is REQUIRED to follow the
specification and security advisory mandated from the respective elliptic curve
specification.


# Supported Public Key Algorithms

This section specifies the composite ML-KEM + ECC and ML-DSA + ECC schemes as
well as the standalone SLH-DSA signature scheme. The composite schemes are
fully specified via their algorithm ID. The SLH-DSA signature schemes are
fully specified by their algorithm ID and an additional parameter ID.

## Algorithm Specifications

For encryption, the following composite KEM schemes are specified:

{: title="KEM algorithm specifications" #kem-alg-specs}
ID | Algorithm                          | Requirement | Definition
--:| ---------------------------------- | ----------- | --------------------
29 | ML-KEM-768  + X25519               | MUST        | {{ecc-mlkem}}
30 | ML-KEM-1024 + X448                 | SHOULD      | {{ecc-mlkem}}
31 | ML-KEM-768  + ECDH-NIST-P-256      | MAY         | {{ecc-mlkem}}
32 | ML-KEM-1024 + ECDH-NIST-P-384      | MAY         | {{ecc-mlkem}}
33 | ML-KEM-768  + ECDH-brainpoolP256r1 | MAY         | {{ecc-mlkem}}
34 | ML-KEM-1024 + ECDH-brainpoolP384r1 | MAY         | {{ecc-mlkem}}

For signatures, the following (composite) signature schemes are specified:

{: title="Signature algorithm specifications" #sig-alg-specs}
ID | Algorithm                          | Requirement | Definition
--:| ---------------------------------- | ----------- | --------------------
35 | ML-DSA-65 + Ed25519                | MUST        | {{ecc-mldsa}}
36 | ML-DSA-87 + Ed448                  | SHOULD      | {{ecc-mldsa}}
37 | ML-DSA-65 + ECDSA-NIST-P-256       | MAY         | {{ecc-mldsa}}
38 | ML-DSA-87 + ECDSA-NIST-P-384       | MAY         | {{ecc-mldsa}}
39 | ML-DSA-65 + ECDSA-brainpoolP256r1  | MAY         | {{ecc-mldsa}}
40 | ML-DSA-87 + ECDSA-brainpoolP384r1  | MAY         | {{ecc-mldsa}}
41 | SLH-DSA-SHA2                       | SHOULD      | {{slhdsa}}
42 | SLH-DSA-SHAKE                      | MAY         | {{slhdsa}}

## Parameter Specification

### SLH-DSA-SHA2

For the SLH-DSA-SHA2 signature algorithm from {{sig-alg-specs}}, the following
parameters are specified:

{: title="SLH-DSA-SHA2 security parameters" #slhdsa-param-sha2}
Parameter ID | Parameter
------------:| -------------------------
1            | SLH-DSA-SHA2-128s
2            | SLH-DSA-SHA2-128f
3            | SLH-DSA-SHA2-192s
4            | SLH-DSA-SHA2-192f
5            | SLH-DSA-SHA2-256s
6            | SLH-DSA-SHA2-256f

All security parameters inherit the requirement of SLH-DSA-SHA2 from
{{sig-alg-specs}}. That is, implementations SHOULD implement the parameters
specified in {{slhdsa-param-sha2}}. The values `0x00` and `0xFF` are reserved
for future extensions.

### SLH-DSA-SHAKE

For the SLH-DSA-SHAKE signature algorithm from {{sig-alg-specs}}, the
following parameters are specified:

{: title="SLH-DSA-SHAKE security parameters" #slhdsa-param-shake}
Parameter ID | Parameter
------------:| --------------------------
1            | SLH-DSA-SHAKE-128s
2            | SLH-DSA-SHAKE-128f
3            | SLH-DSA-SHAKE-192s
4            | SLH-DSA-SHAKE-192f
5            | SLH-DSA-SHAKE-256s
6            | SLH-DSA-SHAKE-256f

All security parameters inherit the requirement of SLH-DSA-SHAKE from
{{sig-alg-specs}}. That is, implementations MAY implement the parameters
specified in {{slhdsa-param-shake}}. The values `0x00` and `0xFF` are reserved
for future extensions.

# Algorithm Combinations

## Composite KEMs

ML-KEM + ECC public-key encryption is meant to involve both the ML-KEM and an
ECC-based KEM in an a priori non-separable manner. This is achieved via KEM
combination, i.e. both key encapsulations/decapsulations are performed in
parallel, and the resulting key shares are fed into a key combiner to produce a
single shared secret for message encryption.

## Parallel Public-Key Encryption {#no-pq-t-parallel-encryption}

As explained in {{non-composite-multi-alg}}, the OpenPGP protocol inherently
supports parallel encryption to different keys of the same recipient.
Implementations MUST NOT encrypt a message with a purely traditional public-key
encryption key of a recipient if it is encrypted with a PQ/T key of the same
recipient.

## Composite Signatures

ML-DSA + ECC signatures are meant to contain both the ML-DSA and the ECC
signature data, and an implementation MUST validate both algorithms to state
that a signature is valid.

## Multiple Signatures {#multiple-signatures}

The OpenPGP message format allows multiple signatures of a message, i.e. the
attachment of multiple signature packets.

An implementation MAY sign a message with a traditional key and a PQ(/T) key
from the same sender. This ensures backwards compatibility due to
{{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5, since a legacy
implementation without PQ(/T) support can fall back on the traditional
signature.

Newer implementations with PQ(/T) support MAY ignore the traditional
signature(s) during validation.

Implementations SHOULD consider the message correctly signed if at least one of
the non-ignored signatures validates successfully.

\[Note to the reader: The last requirement, that one valid signature is
sufficient to identify a message as correctly signed, is an interpretation of
{{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5.\]

# Composite KEM schemes

## Building Blocks

### ECC-Based KEMs {#ecc-kem}

In this section we define the encryption, decryption, and data formats for the
ECDH component of the composite algorithms.

{{tab-ecdh-cfrg-artifacts}}, {{tab-ecdh-nist-artifacts}}, and
{{tab-ecdh-brainpool-artifacts}} describe the ECC-KEM parameters and artifact
lengths. The artefacts in {{tab-ecdh-cfrg-artifacts}} follow the encodings
described in [RFC7748].

{: title="Montgomery curves parameters and artifact lengths" #tab-ecdh-cfrg-artifacts}
|                        | X25519                                     | X448                                       |
|------------------------|--------------------------------------------|--------------------------------------------|
| Algorithm ID reference | 29                                         | 30                                         |
| Field size             | 32 octets                                  | 56 octets                                  |
| ECC-KEM                | x25519Kem ({{x25519-kem}})                 | x448Kem ({{x448-kem}})                     |
| ECDH public key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH secret key        | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH ephemeral         | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| ECDH share             | 32 octets [RFC7748]                        | 56 octets [RFC7748]                        |
| Key share              | 32 octets                                  | 64 octets                                  |
| Hash                   | SHA3-256                                   | SHA3-512                                   |

{: title="NIST curves parameters and artifact lengths" #tab-ecdh-nist-artifacts}
|                        | NIST P-256                                             | NIST P-384                                             |
|------------------------|--------------------------------------------------------|--------------------------------------------------------|
| Algorithm ID reference | 31                                                     | 32                                                     |
| Field size             | 32 octets                                              | 48 octets                                              |
| ECC-KEM                | ecdhKem ({{ecdh-kem}})                                 | ecdhKem ({{ecdh-kem}})                                 |
| ECDH public key        | 65 octets of SEC1-encoded public point                 | 97 octets of SEC1-encoded public point                 |
| ECDH secret key        | 32 octets big-endian encoded secret scalar             | 48 octets big-endian encoded secret scalar             |
| ECDH ephemeral         | 65 octets of SEC1-encoded ephemeral point              | 97 octets of SEC1-encoded ephemeral point              |
| ECDH share             | 65 octets of SEC1-encoded shared point                 | 97 octets of SEC1-encoded shared point                 |
| Key share              | 32 octets                                              | 64 octets                                              |
| Hash                   | SHA3-256                                               | SHA3-512                                               |

{: title="Brainpool curves parameters and artifact lengths" #tab-ecdh-brainpool-artifacts}
|                        | brainpoolP256r1                                        | brainpoolP384r1                                        |
|------------------------|--------------------------------------------------------|--------------------------------------------------------|
| Algorithm ID reference | 33                                                     | 34                                                     |
| Field size             | 32 octets                                              | 48 octets                                              |
| ECC-KEM                | ecdhKem ({{ecdh-kem}})                                 | ecdhKem ({{ecdh-kem}})                                 |
| ECDH public key        | 65 octets of SEC1-encoded public point                 | 97 octets of SEC1-encoded public point                 |
| ECDH secret key        | 32 octets big-endian encoded secret scalar             | 48 octets big-endian encoded secret scalar             |
| ECDH ephemeral         | 65 octets of SEC1-encoded ephemeral point              | 97 octets of SEC1-encoded ephemeral point              |
| ECDH share             | 65 octets of SEC1-encoded shared point                 | 97 octets of SEC1-encoded shared point                 |
| Key share              | 32 octets                                              | 64 octets                                              |
| Hash                   | SHA3-256                                               | SHA3-512                                               |

The SEC1 format for point encoding is defined in {{sec1-format}}.

The various procedures to perform the operations of an ECC-based KEM are
defined in the following subsections. Specifically, each of these subsections
defines the instances of the following operations:

    (eccCipherText, eccKeyShare) <- ECC-KEM.Encaps(eccPublicKey)

and

    (eccKeyShare) <- ECC-KEM.Decaps(eccPrivateKey, eccCipherText)

To instantiate `ECC-KEM`, one must select a parameter set from
{{tab-ecdh-cfrg-artifacts}}, {{tab-ecdh-nist-artifacts}}, or
{{tab-ecdh-brainpool-artifacts}}.

#### X25519-KEM {#x25519-kem}

The encapsulation and decapsulation operations of `x25519kem` are described
using the function `X25519()` and encodings defined in [RFC7748]. The
`eccPrivateKey` is denoted as `r`, the `eccPublicKey` as `R`, they are subject
to the equation `R = X25519(r, U(P))`. Here, `U(P)` denotes the u-coordinate of
the base point of Curve25519.

The operation `x25519Kem.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X25519(v,U(P))` where `v`
    is a random scalar

 2. Compute the shared coordinate `X = X25519(v, R)` where `R` is the public key
    `eccPublicKey`

 3. Set the output `eccCipherText` to `V`

 4. Set the output `eccKeyShare` to `SHA3-256(X || eccCipherText || eccPublicKey)`

The operation `x25519Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X25519(r, V)`, where `r` is the
    `eccPrivateKey` and `V` is the `eccCipherText`

 2. Set the output `eccKeyShare` to `SHA3-256(X || eccCipherText || eccPublicKey)`

#### X448-KEM {#x448-kem}

The encapsulation and decapsulation operations of `x448kem` are described using
the function `X448()` and encodings defined in [RFC7748]. The `eccPrivateKey`
is denoted as `r`, the `eccPublicKey` as `R`, they are subject to the equation
`R = X25519(r, U(P))`. Here, `U(P)` denotes the u-coordinate of the base point
of Curve448.

The operation `x448.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X448(v,U(P))` where `v`
    is a random scalar

 2. Compute the shared coordinate `X = X448(v, R)` where `R` is the public key
    `eccPublicKey`

 3. Set the output `eccCipherText` to `V`

 4. Set the output `eccKeyShare` to `SHA3-512(X || eccCipherText || eccPublicKey)`

The operation `x448Kem.Decaps()` is defined as follows:

 1. Compute the shared coordinate `X = X448(r, V)`, where `r` is the
    `eccPrivateKey` and `V` is the `eccCipherText`

 2. Set the output `eccKeyShare` to `SHA3-512(X || eccCipherText || eccPublicKey)`

#### ECDH-KEM {#ecdh-kem}

The operation `ecdhKem.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V=vG`} as defined in
    {{SP800-186}} or {{RFC5639}} where `v` is a random scalar

 2. Compute the shared point `S = vR`, where `R` is the component public key
    `eccPublicKey`, according to {{SP800-186}} or {{RFC5639}}

 3. Extract the `X` coordinate from the SEC1 encoded point `S = 04 || X || Y`
    as defined in section {{sec1-format}}

 4. Set the output `eccCipherText` to the SEC1 encoding of `V`

 5. Set the output `eccKeyShare` to `Hash(X || eccCipherText || eccPublicKey)`, with `Hash`
    chosen according to {{tab-ecdh-nist-artifacts}} or
    {{tab-ecdh-brainpool-artifacts}}

The operation `ecdhKem.Decaps()` is defined as follows:

 1. Compute the shared Point `S` as `rV`, where `r` is the `eccPrivateKey` and
    `V` is the `eccCipherText`, according to {{SP800-186}} or {{RFC5639}}

 2. Extract the `X` coordinate from the SEC1 encoded point `S = 04 || X || Y`
    as defined in section {{sec1-format}}

 3. Set the output `eccKeyShare` to `Hash(X || eccCipherText || eccPublicKey)`, with `Hash`
    chosen according to {{tab-ecdh-nist-artifacts}} or
    {{tab-ecdh-brainpool-artifacts}}

### ML-KEM {#mlkem-ops}

ML-KEM features the following operations:

    (mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemEncapsKey)

and

    (mlkemKeyShare) <- ML-KEM.Decaps(mlkemCipherText, mlkemDecapsKey)

The above are the operations `ML-KEM.Encaps` and `ML-KEM.Decaps` defined in
[FIPS-203]. Note that `mlkemEncapsKey` is public and `mlkemDecapsKey` is
private keying material.

ML-KEM has the parameterization with the corresponding artifact lengths in
octets as given in {{tab-mlkem-artifacts}}. All artifacts are encoded as
defined in [FIPS-203].

{: title="ML-KEM parameters artifact lengths in octets" #tab-mlkem-artifacts}
Algorithm ID reference | ML-KEM      | Public key | Secret key | Ciphertext | Key share
----------------------:| ----------- | ---------- | ---------- | ---------- | ---------
29, 31, 33             | ML-KEM-768  | 1184       | 2400       | 1088       | 32
30, 32, 34             | ML-KEM-1024 | 1568       | 3168       | 1568       | 32

To instantiate `ML-KEM`, one must select a parameter set from the column
"ML-KEM" of {{tab-mlkem-artifacts}}.

The procedure to perform `ML-KEM.Encaps()` is as follows:

 1. Extract the encapsulation key `mlkemEncapsKey` that is part of the
    recipient's composite public key

 2. Invoke `(mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemEncapsKey)`

 3. Set `mlkemCipherText` as the ML-KEM ciphertext

 4. Set `mlkemKeyShare` as the ML-KEM symmetric key share

The procedure to perform `ML-KEM.Decaps()` is as follows:

 1. Invoke `mlkemKeyShare <-  ML-KEM.Decaps(mlkemCipherText, mlkemDecapsKey)`

 2. Set `mlkemKeyShare` as the ML-KEM symmetric key share

## Composite Encryption Schemes with ML-KEM {#ecc-mlkem}

{{kem-alg-specs}} specifies the following ML-KEM + ECC composite public-key
encryption schemes:

{: title="ML-KEM + ECC composite schemes" #tab-mlkem-ecc-composite}
Algorithm ID reference | ML-KEM       | ECC-KEM   | ECC-KEM curve
----------------------:| ------------ | --------- | --------------
29                     | ML-KEM-768   | x25519Kem | Curve25519
30                     | ML-KEM-1024  | x448Kem   | Curve448
31                     | ML-KEM-768   | ecdhKem   | NIST P-256
32                     | ML-KEM-1024  | ecdhKem   | NIST P-384
33                     | ML-KEM-768   | ecdhKem   | brainpoolP256r1
34                     | ML-KEM-1024  | ecdhKem   | brainpoolP384r1

The ML-KEM + ECC composite public-key encryption schemes are built according to
the following principal design:

 - The ML-KEM encapsulation algorithm is invoked to create a ML-KEM ciphertext
   together with a ML-KEM symmetric key share.

 - The encapsulation algorithm of an ECC-based KEM, namely one out of
   X25519-KEM, X448-KEM, or ECDH-KEM is invoked to create an ECC ciphertext
   together with an ECC symmetric key share.

 - A Key-Encryption-Key (KEK) is computed as the output of a key combiner that
   receives as input both of the above created symmetric key shares and the
   protocol binding information.

 - The session key for content encryption is then wrapped as described in
   {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The PKESK package's algorithm-specific parts are made up of the ML-KEM
   ciphertext, the ECC ciphertext, and the wrapped session key.

### Fixed information {#kem-fixed-info}

For the composite KEM schemes defined in {{kem-alg-specs}} the following
procedure, justified in {{sec-fixed-info}}, MUST be used to derive a string to
use as binding between the KEK and the communication parties.

    //   Input:
    //   algID     - the algorithm ID encoded as octet

    fixedInfo = algID

### Key combiner {#kem-key-combiner}

For the composite KEM schemes defined in {{kem-alg-specs}} the following
procedure MUST be used to compute the KEK that wraps a session key. The
construction is a one-step key derivation function compliant to {{SP800-56C}}
Section 4, based on KMAC256 {{SP800-185}}. It is given by the following
algorithm.

    //   multiKeyCombine(eccKeyShare, eccCipherText,
    //                   mlkemKeyShare, mlkemCipherText,
    //                   fixedInfo, oBits)
    //
    //   Input:
    //   eccKeyShare     - the ECC key share encoded as an octet string
    //   eccCipherText   - the ECC ciphertext encoded as an octet string
    //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
    //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
    //   fixedInfo       - the fixed information octet string
    //   oBits           - the size of the output keying material in bits
    //
    //   Constants:
    //   domSeparation       - the UTF-8 encoding of the string
    //                         "OpenPGPCompositeKeyDerivationFunction"
    //   counter             - the fixed 4 byte value 0x00000001
    //   customizationString - the UTF-8 encoding of the string "KDF"

    eccData = eccKeyShare || eccCipherText
    mlkemData = mlkemKeyShare || mlkemCipherText
    encData = counter || eccData || mlkemData || fixedInfo

    MB = KMAC256(domSeparation, encData, oBits, customizationString)

Note that the values `eccKeyShare` defined in {{ecc-kem}} and `mlkemKeyShare`
defined in {{mlkem-ops}} already use the relative ciphertext in the
derivation. The ciphertext is by design included again in the key combiner to
provide a robust security proof.

The value of `domSeparation` is the UTF-8 encoding of the string
"OpenPGPCompositeKeyDerivationFunction" and MUST be the following octet sequence:

    domSeparation := 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65
                     4B 65 79 44 65 72 69 76 61 74 69 6F 6E 46 75 6E
                     63 74 69 6F 6E

The value of `counter` MUST be set to the following octet sequence:

    counter :=  00 00 00 01

The value of `fixedInfo` MUST be set according to {{kem-fixed-info}}.

The value of `customizationString` is the UTF-8 encoding of the string "KDF"
and MUST be set to the following octet sequence:

    customizationString := 4B 44 46

### Key generation procedure {#ecc-mlkem-generation}

The implementation MUST independently generate the ML-KEM and the ECC component
keys. ML-KEM key generation follows the specification [FIPS-203] and the
artifacts are encoded as fixed-length octet strings as defined in
{{mlkem-ops}}. For ECC this is done following the relative specification in
{{RFC7748}}, {{SP800-186}}, or {{RFC5639}}, and encoding the outputs as
fixed-length octet strings in the format specified in
{{tab-ecdh-cfrg-artifacts}}, {{tab-ecdh-nist-artifacts}}, or
{{tab-ecdh-brainpool-artifacts}}.

### Encryption procedure {#ecc-mlkem-encryption}

The procedure to perform public-key encryption with a ML-KEM + ECC composite
scheme is as follows:

 1. Take the recipient's authenticated public-key packet `pkComposite` and
   `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite`

 3. Extract the `eccPublicKey` and `mlkemEncapsKey` component from the
    algorithm specific data encoded in `pkComposite` with the format specified in
    {{mlkem-ecc-key}}.

 4. Instantiate the ECC-KEM and the ML-KEM depending on the algorithm ID
    according to {{tab-mlkem-ecc-composite}}

 5. Compute `(eccCipherText, eccKeyShare) := ECC-KEM.Encaps(eccPublicKey)`

 6. Compute `(mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemEncapsKey)`

 7. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 8. Compute `KEK := multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, oBits=256)` as
    defined in {{kem-key-combiner}}

 9. Compute `C := AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}}
    that includes a 64 bit integrity check

 10. Output `eccCipherText || mlkemCipherText || len(C) || C`

### Decryption procedure

The procedure to perform public-key decryption with a ML-KEM + ECC composite
scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID and the `encryptedKey`

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `eccPrivateKey` and `mlkemDecapsKey` from the algorithm specific
    data of the own secret key encoded in the format specified in
    {{mlkem-ecc-key}}

 5. Instantiate the ECC-KEM and the ML-KEM depending on the algorithm ID
    according to {{tab-mlkem-ecc-composite}}

 6. Parse `eccCipherText`, `mlkemCipherText`, and `C` from `encryptedKey`
    encoded as `eccCipherText || mlkemCipherText || len(C) || C` as specified
    in {{ecc-mlkem-pkesk}}

 7. Compute `(eccKeyShare) := ECC-KEM.Decaps(eccCipherText, eccPrivateKey)`

 8. Compute `(mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemDecapsKey)`

 9. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 10. Compute `KEK := multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare,
     mlkemCipherText, fixedInfo, oBits=256)` as defined in {{kem-key-combiner}}

 11. Compute `sessionKey := AESKeyUnwrap(KEK, C)`  with AES-256 as per
     {{RFC3394}}, aborting if the 64 bit integrity check fails

 12. Output `sessionKey`

## Packet specifications

### Public-Key Encrypted Session Key Packets (Tag 1) {#ecc-mlkem-pkesk}

The algorithm-specific fields consists of:

 - A fixed-length octet string representing an ECC ephemeral public key in the
   format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the ML-KEM ciphertext, whose length depends
   on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

 - The one-octet algorithm identifier, if it is passed (in the case of a v3
   PKESK packet).

 - A variable-length field containing the wrapped session key:

   - A one-octet size of the following field;

   - The wrapped session key represented as an octet string, i.e., the output
     of the encryption procedure described in {{ecc-mlkem-encryption}}.

Note that unlike most public-key algorithms, in the case of a v3 PKESK packet,
the symmetric algorithm identifier is not encrypted.  Instead, it is prepended
to the encrypted session key in plaintext.  In this case, the symmetric
algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8 or 9).

### Key Material Packets {#mlkem-ecc-key}

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an EC point public key, in the
   point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM encapsulation key, whose
   length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded secret scalar, whose encoding and
   length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM decapsulation key, whose
   length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

# Composite Signature Schemes

## Building blocks

### EdDSA-Based signatures {#eddsa-signature}

To sign and verify with EdDSA the following operations are defined:

    (eddsaSignature) <- EdDSA.Sign(eddsaPrivateKey, dataDigest)

and

    (verified) <- EdDSA.Verify(eddsaPublicKey, eddsaSignature, dataDigest)

The public and private keys, as well as the signature MUST be encoded according
to [RFC8032] as fixed-length octet strings. The following table describes the
EdDSA parameters and artifact lengths:

{: title="EdDSA parameters and artifact lengths in octets" #tab-eddsa-artifacts}
Algorithm ID reference | Curve   | Field size | Public key | Secret key | Signature
----------------------:| ------- | ---------- | ---------- | ---------- | ---------
35                     | Ed25519 | 32         | 32         | 32         | 64
36                     | Ed448   | 57         | 57         | 57         | 114

### ECDSA-Based signatures {#ecdsa-signature}

To sign and verify with ECDSA the following operations are defined:

    (ecdsaSignatureR, ecdsaSignatureS) <- ECDSA.Sign(ecdsaPrivateKey,
                                                     dataDigest)

and

    (verified) <- ECDSA.Verify(ecdsaPublicKey, ecdsaSignatureR,
                               ecdsaSignatureS, dataDigest)

The public keys MUST be encoded in SEC1 format as defined in section
{{sec1-format}}. The secret key, as well as both values `R` and `S` of the
signature MUST each be encoded as a big-endian integer in a fixed-length octet
string of the specified size.

The following table describes the ECDSA parameters and artifact lengths:

{: title="ECDSA parameters and artifact lengths in octets" #tab-ecdsa-artifacts}
Algorithm ID reference | Curve           | Field size | Public key | Secret key | Signature value R | Signature value S
----------------------:| --------------- | ---------- | ---------- | ---------- | ----------------- | -----------------
37                     | NIST P-256      | 32         | 65         | 32         | 32                | 32
38                     | NIST P-384      | 48         | 97         | 48         | 48                | 48
39                     | brainpoolP256r1 | 32         | 65         | 32         | 32                | 32
40                     | brainpoolP384r1 | 48         | 97         | 48         | 48                | 48

### ML-DSA signatures {#mldsa-signature}

For ML-DSA signature generation the default hedged version of `ML-DSA.Sign`
given in [FIPS-204] is used. That is, to sign with ML-DSA the following
operation is defined:

    (mldsaSignature) <- ML-DSA.Sign(mldsaPrivateKey, dataDigest)

For ML-DSA signature verification the algorithm ML-DSA.Verify given in
[FIPS-204] is used.  That is, to verify with ML-DSA the following operation is
defined:

    (verified) <- ML-DSA.Verify(mldsaPublicKey, dataDigest, mldsaSignature)

ML-DSA has the parameterization with the corresponding artifact lengths in
octets as given in {{tab-mldsa-artifacts}}. All artifacts are encoded as
defined in [FIPS-204].

{: title="ML-DSA parameters and artifact lengths in octets" #tab-mldsa-artifacts}
Algorithm ID reference | ML-DSA    | Public key | Secret key | Signature value
----------------------:| --------- | -----------| ---------- | ---------------
35, 37, 39             | ML-DSA-65 | 1952       | 4000       | 3293
36, 38, 40             | ML-DSA-87 | 2592       | 4864       | 4595

## Composite Signature Schemes with ML-DSA {#ecc-mldsa}

### Signature data digest {#mldsa-sig-data-digest}

Signature data is digested prior to signing operations, see
{{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4. Composite ML-DSA + ECC
signatures MUST use the associated hash algorithm as specified in
{{tab-mldsa-hash}} for the signature data digest. Signatures using other hash
algorithms MUST be considered invalid.

An implementation supporting a specific ML-DSA + ECC algorithm MUST also
support the matching hash algorithm.

{: title="Binding between ML-DSA and signature data digest" #tab-mldsa-hash}
Algorithm ID reference | Hash function | Hash function ID reference
----------------------:| ------------- | --------------------------
35, 37, 39             | SHA3-256      | 12
36, 38, 40             | SHA3-512      | 14

### Key generation procedure {#ecc-mldsa-generation}

The implementation MUST independently generate the ML-DSA and the ECC
component keys. ML-DSA key generation follows the specification
[FIPS-204] and the artifacts are encoded as fixed-length octet strings as
defined in {{mldsa-signature}}. For ECC this is done following the relative
specification in {{RFC7748}}, {{SP800-186}}, or {{RFC5639}}, and encoding the
artifacts as specified in {{eddsa-signature}} or {{ecdsa-signature}} as
fixed-length octet strings.

### Signature Generation

To sign a message `M` with ML-DSA + EdDSA the following sequence of
operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}}
    Section 5.2.4

 2. Create the EdDSA signature over `dataDigest` with `EdDSA.Sign()` from
    {{eddsa-signature}}

 3. Create the ML-DSA signature over `dataDigest` with `ML-DSA.Sign()` from
    {{mldsa-signature}}

 4. Encode the EdDSA and ML-DSA signatures according to the packet structure
    given in {{ecc-mldsa-sig-packet}}.

To sign a message `M` with ML-DSA + ECDSA the following sequence of
operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}}
    Section 5.2.4

 2. Create the ECDSA signature over `dataDigest` with `ECDSA.Sign()` from
    {{ecdsa-signature}}

 3. Create the ML-DSA signature over `dataDigest` with `ML-DSA.Sign()` from
    {{mldsa-signature}}

 4. Encode the ECDSA and ML-DSA signatures according to the packet structure
    given in {{ecc-mldsa-sig-packet}}.

### Signature Verification

To verify a ML-DSA + EdDSA signature the following sequence of operations
has to be performed:

 1. Verify the EdDSA signature with `EdDSA.Verify()` from {{eddsa-signature}}

 2. Verify the ML-DSA signature with `ML-DSA.Verify()` from {{mldsa-signature}}

To verify a ML-DSA + ECDSA signature the following sequence of operations has
to be performed:

 1. Verify the ECDSA signature with `ECDSA.Verify()` from {{ecdsa-signature}}

 2. Verify the ML-DSA signature with `ML-DSA.Verify()` from {{mldsa-signature}}

As specified in {{composite-signatures}} an implementation MUST validate both
signatures, i.e. EdDSA/ECDSA and ML-DSA, to state that a composite ML-DSA + ECC
signature is valid.

## Packet Specifications

### Signature Packet (Tag 2) {#ecc-mldsa-sig-packet}

The composite ML-DSA + ECC schemes MUST be used only with v6 signatures, as
defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific v6 signature parameters for ML-DSA + EdDSA signatures
consists of:

 - A fixed-length octet string representing the EdDSA signature, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific v6 signature parameters for ML-DSA + ECDSA signatures
consists of:

 - A fixed-length octet string of the big-endian encoded ECDSA value `R`, whose
   length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the big-endian encoded ECDSA value `S`, whose
   length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

### Key Material Packets

The composite ML-DSA + ECC schemes MUST be used only with v6 keys, as defined
in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key for ML-DSA + EdDSA keys is this series of
values:

 - A fixed-length octet string representing the EdDSA public key, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific private key for ML-DSA + EdDSA keys is this series of
values:

 - A fixed-length octet string representing the EdDSA secret key, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific public key for ML-DSA + ECDSA keys is this series of
values:

 - A fixed-length octet string representing the ECDSA public key in SEC1
   format, as specified in section {{sec1-format}} and with length specified in
   {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific private key for ML-DSA + ECDSA keys is this series of
values:

 - A fixed-length octet string representing the ECDSA secret key as a
   big-endian encoded integer, whose length depends on the algorithm used as
   specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key, whose length
   depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

# SLH-DSA

## The SLH-DSA Algorithms {#slhdsa}

The following table describes the SLH-DSA parameters and artifact lengths:

{: title="SLH-DSA parameters and artifact lengths in octets. The values equally apply to the parameter IDs of SLH-DSA-SHA2 and SLH-DSA-SHAKE." #slhdsa-artifact-lengths}
Parameter ID reference | Parameter name suffix | SLH-DSA public key | SLH-DSA secret key | SLH-DSA signature
----------------------:| ---------------------:| ------------------ | ------------------ | ------------------
1                      | 128s                  | 32                 | 64                 | 7856
2                      | 128f                  | 32                 | 64                 | 17088
3                      | 192s                  | 48                 | 96                 | 16224
4                      | 192f                  | 48                 | 96                 | 35664
5                      | 256s                  | 64                 | 128                | 29792
6                      | 256f                  | 64                 | 128                | 49856

### Signature Data Digest {#slhdsa-sig-data-digest}

Signature data is digested prior to signing operations, see
{{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4. SLH-DSA signatures MUST use
the associated hash algorithm as specified in {{tab-slhdsa-hash}} for the
signature data digest. Signatures using other hash algorithms MUST be
considered invalid.

An implementation supporting a specific SLH-DSA algorithm and parameter MUST
also support the matching hash algorithm.

{: title="Binding between SLH-DSA and signature data digest" #tab-slhdsa-hash}
Algorithm ID reference | Parameter ID reference | Hash function | Hash function ID reference
----------------------:| ---------------------- | ------------- | --------------------------
41                     | 1, 2                   | SHA-256       | 8
41                     | 3, 4, 5, 6             | SHA-512       | 10
42                     | 1, 2                   | SHA3-256      | 12
42                     | 3, 4, 5, 6             | SHA3-512      | 14

### Key generation

SLH-DSA key generation is performed via the algorithm `SLH-DSA.KeyGen` as
specified in {{FIPS-205}}, and the artifacts are encoded as fixed-length octet
strings as defined in {{slhdsa}}.

### Signature Generation

SLH-DSA signature generation is performed via the algorithm `SLH-DSA.Sign` as
specified in {{FIPS-205}}. The variable `opt_rand` is set to `PK.seed`. See
also {{slhdsa-sec-cons}}.

An implementation MUST set the Parameter ID in the signature equal to the
issuing private key Parameter ID.

### Signature Verification

SLH-DSA signature verification is performed via the algorithm `SLH-DSA.Verify`
as specified in {{FIPS-205}}.

An implementation MUST check that the Parameter ID in the signature and in the
key match when verifying.

## Packet specifications

###  Signature Packet (Tag 2)

The SLH-DSA scheme MUST be used only with v6 signatures, as defined in
[I-D.ietf-openpgp-crypto-refresh] Section 5.2.3.

The algorithm-specific v6 Signature parameters consists of:

 - A one-octet value specifying the SLH-DSA parameter ID defined in
   {{slhdsa-param-sha2}} and {{slhdsa-param-shake}}. The values `0x00` and
   `0xFF` are reserved for future extensions.

 - A fixed-length octet string of the SLH-DSA signature value, whose length
   depends on the parameter ID in the format specified in
   {{slhdsa-artifact-lengths}}.

### Key Material Packets

The SLH-DSA scheme MUST be used only with v6 keys, as defined in
[I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key is this series of values:

 - A one-octet value specifying the SLH-DSA parameter ID defined in
   {{slhdsa-param-sha2}} and {{slhdsa-param-shake}}. The values `0x00` and
   `0xFF` are reserved for future extensions.

 - A fixed-length octet string containing the SLH-DSA public key, whose length
   depends on the parameter ID as specified in {{slhdsa-artifact-lengths}}.

The algorithm-specific private key is this value:

 - A fixed-length octet string containing the SLH-DSA secret key, whose length
   depends on the parameter ID as specified in {{tab-ecdsa-artifacts}}.

# Migration Considerations

The post-quantum KEM algorithms defined in {{kem-alg-specs}} and the signature
algorithms defined in {{sig-alg-specs}} are a set of new public key algorithms
that extend the algorithm selection of {{I-D.ietf-openpgp-crypto-refresh}}.
During the transition period, the post-quantum algorithms will not be supported
by all clients. Therefore various migration considerations must be taken into
account, in particular backwards compatibility to existing implementations that
have not yet been updated to support the post-quantum algorithms.

## Key preference

Implementations SHOULD prefer PQ(/T) keys when multiple options are available.

For instance, if encrypting for a recipient for which both a valid PQ/T and a
valid ECC certificate are available, the implementation SHOULD choose the PQ/T
certificate. In case a certificate has both a PQ/T and an ECC
encryption-capable valid subkey, the PQ/T subkey SHOULD be preferred.

An implementation MAY sign with both a PQ(/T) and an ECC key using multiple
signatures over the same data as described in {{multiple-signatures}}.
Signing only with PQ(/T) key material is not backwards compatible.

Note that the confidentiality of a message is not post-quantum secure when
encrypting to multiple recipients if at least one recipient does not support
PQ/T encryption schemes. An implementation SHOULD NOT abort the encryption
process in this case to allow for a smooth transition to post-quantum
cryptography.

## Key generation strategies

It is REQUIRED to generate fresh secrets when generating PQ(/T) keys. Reusing
key material from existing ECC keys in PQ(/T) keys does not provide backwards
compatibility, and the fingerprint will differ.

An OpenPGP (v6) certificate is composed of a certification-capable primary key
and one or more subkeys for signature, encryption, and authentication.
Two migration strategies are recommended:

1. Generate two independent certificates, one for PQ(/T)-capable
implementations, and one for legacy implementations. Implementations not
understanding PQ(/T) certificates can use the legacy certificate, while
PQ(/T)-capable implementations will prefer the newer certificate. This allows
having an older v4 or v6 ECC certificate for compatibility and a v6 PQ(/T)
certificate, at a greater complexity in key distribution.

2. Attach PQ(/T) encryption and signature subkeys to an existing v6 ECC
certificate. Implementations understanding PQ(/T) will be able to parse and use
the subkeys, while PQ(/T)-incapable implementations can gracefully ignore them.
This simplifies key distribution, as only one certificate needs to be
communicated and verified, but leaves the primary key vulnerable to quantum
computer attacks.

# Security Considerations

## Hashing in ECC-KEM

Our construction of the ECC-KEMs, in particular the inclusion of
`eccCipherText` in the final hashing step in encapsulation and decapsulation
that produces the `eccKeyShare`, is standard and known as hashed ElGamal key
encapsulation, a hashed variant of ElGamal encryption. It ensures IND-CCA2
security in the random oracle model under some Diffie-Hellman intractability
assumptions [CS03]. The additional inclusion of `eccPublicKey` follows the
security advice in Section 6.1 of {{RFC7748}}.

## Key combiner {#sec-key-combiner}

For the key combination in {{kem-key-combiner}} this specification limits
itself to the use of KMAC. The sponge construction used by KMAC was proven to
be indifferentiable from a random oracle {{BDPA08}}. This means, that in
contrast to SHA2, which uses a Merkle-Damgard construction, no HMAC-based
construction is required for key combination. Except for a domain separation it
is sufficient to simply process the concatenation of any number of key shares
when using a sponge-based construction like KMAC. The construction using KMAC
ensures a standardized domain separation. In this case, the processed message
is then the concatenation of any number of key shares.

More precisely, for a given capacity `c` the indifferentiability proof shows
that assuming there are no weaknesses found in the Keccak permutation, an
attacker has to make an expected number of `2^(c/2)` calls to the permutation
to tell KMAC from a random oracle. For a random oracle, a difference in only a
single bit gives an unrelated, uniformly random output. Hence, to be able to
distinguish a key `K`, derived from shared keys `K1` and `K2` (and ciphertexts
`C1` and `C2`) as

    K = KMAC(domainSeparation, counter || K1 || C1 || K2 || C2 || fixedInfo,
             outputBits, customization)

from a random bit string, an adversary has to know (or correctly guess) both
key shares `K1` and `K2`, entirely.

The proposed construction in {{kem-key-combiner}} preserves IND-CCA2 of any of
its ingredient KEMs, i.e. the newly formed combined KEM is IND-CCA2 secure as
long as at least one of the ingredient KEMs is. Indeed, the above stated
indifferentiability from a random oracle qualifies Keccak as a split-key
pseudorandom function as defined in {{GHP18}}. That is, Keccak behaves like a
random function if at least one input shared secret is picked uniformly at
random. Our construction can thus be seen as an instantiation of the IND-CCA2
preserving Example 3 in Figure 1 of {{GHP18}}, up to some reordering of input
shared secrets and ciphertexts. In the random oracle setting, the reordering
does not influence the arguments in {{GHP18}}.

## Domain separation and binding {#sec-fixed-info}

The `domSeparation` information defined in {{kem-key-combiner}} provides the
domain separation for the key combiner construction. This ensures that the
input keying material is used to generate a KEK for a specific purpose or
context.

The `fixedInfo` defined in {{kem-fixed-info}} binds the derived KEK to the
chosen algorithm and communication parties. The algorithm ID identifies
univocally the algorithm, the parameters for its instantiation, and the length
of all artifacts, including the derived key.

This is in line with the Recommendation for ECC in section 5.5 of
[SP800-56A]. Other fields included in the recommendation are not relevant
for the OpenPGP protocol, since the sender is not required to have a key of
their own, there are no pre-shared secrets, and all the other parameters are
univocally defined by the algorithm ID.

Furthermore, we do not require the recipients public key into the key combiner
as the public key material is already included in the component key derivation
functions.
Given two KEMs which we assume to be multi-user secure, we combine their outputs
using a KEM-combiner:

    K = H(K1, C1, K2, C2), C = (C1, C2)

Our aim is to preserve multi-user security. A common approach to this is to add
the public key into the key derivation for K. However, it turns out that this is
not necessary here. To break security of the combined scheme in the multi-user
setting, the adversary has to distinguish a set of challenge keys

  K*_u = H(K1*_u, C1*_u, K2*_u, C2*_u)

for users u in some set from random, also given ciphertexts `C*_u = (C1*_u,
C2*_u)`. For each of these K* it holds that if the adversary never makes a
query

    H(K1*_u, C1*_u, K2*_u, C2*_u)

they have a zero advantage over guessing.

The only multi-user advantage that the adversary could gain therefore consists
of queries to H that are meaningful for two different users u1 != u2 and their
associated public keys. This is only the case if

    (c1*_u1, c2*_u1) = (c1*_u2, c2*_u2)

as the ciphertext values decide for which challenge the query is meaningful.
This means that a ciphertext collision is needed between challenges. Assuming
that the randomness used in the generation of the two challenges is
uncorrelated, this is negligible.

In consequence, the ciphertexts already work sufficiently well as
domain-separator.

## SLH-DSA Message Randomizer {#slhdsa-sec-cons}

The specification of SLH-DSA {{FIPS-205}} prescribes an optional
non-deterministic message randomizer. This is not used in this specification,
as OpenPGP v6 signatures already provide a salted signature data digest of the
appropriate size.

## Binding hashes in signatures with signature algorithms

In order not to extend the attack surface, we bind the hash algorithm used for
signature data digestion to the hash algorithm used internally by the signature
algorithm.

ML-DSA internally uses a SHAKE256 digest, therefore we require SHA3 in the
ML-DSA + ECC signature packet, see {{mldsa-sig-data-digest}}.

In the case of SLH-DSA the internal hash algorithm varies based on the
algorithm and parameter ID, see {{slhdsa-sig-data-digest}}.


# Additional considerations

## Performance Considerations for SLH-DSA {#performance-considerations}

This specification introduces both ML-DSA + ECC as well as SLH-DSA as PQ(/T)
signature schemes.

Generally, it can be said that ML-DSA + ECC provides a performance in terms of
execution time and space requirements that is close to that of traditional ECC
signature schemes. Implementers may want to offer SLH-DSA for applications
where a higher degree of trust in the signature scheme is required. However,
SLH-DSA has performance characteristics in terms of execution time of the
signature generation as well as space requirements for the signature that can
be, depending on the parameter choice, far greater than those of traditional or
ML-DSA + ECC signature schemes.

Pertaining to the execution time, the particularly costly operation in SLH-DSA
is the signature generation. In order to achieve short signature generation
times, one of the parameter sets with the name ending in the letter "f" for
"fast" should be chosen. This comes at the expense of a larger signature size.

In order to minimize the space requirements of a SLH-DSA signature, a parameter
set ending in "s" for "small" should be chosen. This comes at the expense of a
longer signature generation time.

# IANA Considerations

IANA will add the following registries to the `Pretty Good Privacy (PGP)`
registry group at https://www.iana.org/assignments/pgp-parameters:

- Registry name: `SLH-DSA-SHA2 parameters`

  Registration procedure: SPECIFICATION REQUIRED [RFC8126]

  Values defined in this document, {{slhdsa-param-sha2}}.

- Registry name: `SLH-DSA-SHAKE parameters`

  Registration procedure: SPECIFICATION REQUIRED [RFC8126]

  Values defined in this document, {{slhdsa-param-shake}}.

Furthermore IANA will add the algorithm IDs defined in {{kem-alg-specs}} and
{{sig-alg-specs}} to the  registry `Public Key Algorithms`.

# Contributors

Stephan Ehlen (BSI)<br>
Carl-Daniel Hailfinger (BSI)<br>
Andreas Huelsing (TU Eindhoven)<br>
Johannes Roth (MTG AG)

--- back

# Acknowledgments
{:numbered="false"}

Thanks to Daniel Huigens and Evangelos Karatsiolis for the early review and
feedback on this document.
