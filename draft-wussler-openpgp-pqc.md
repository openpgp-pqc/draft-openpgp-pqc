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

  KYBER-Subm:
      title: CRYSTALS-Kyber (version 3.02) - Submission to round 3 of the NIST post-quantum project
      author:
        -
          ins: R. Avanzi
        -
          ins: J. Bos
        -
          ins: L. Ducas
        -
          ins: E. Kiltz
        -
          ins: T. Lepoint
        -
          ins: V. Lyubashevsky
        -
          ins: J. M. Schanck
        -
          ins: P. Schwabe
        -
          ins: G. Seiler
        -
          ins: D. Stehle
      date: 2021-08-04

  DILITHIUM-Subm:
      title: CRYSTALS-Dilithium - Algorithm Specifications and Supporting Documentation (Version 3.1)
      author:
        -
          ins: L. Ducas
        -
          ins: E. Kiltz
        -
          ins: T. Lepoint
        -
          ins: V. Lyubashevsky
        -
          ins: P. Schwabe
        -
          ins: G. Seiler
        -
          ins: D. Stehle
      date: 2021-02-08

  SPHINCS-Subm:
      title: SPHINCS+ - Submission to the 3rd round of the NIST post-quantum project. v3.1
      author:
        -
          ins: J. Aumasson
        -
          ins: D. J. Bernstein
        -
          ins: W. Beullens
        -
          ins: C. Dobraunig
        -
          ins: M. Eichlseder
        -
          ins: S. Fluhrer
        -
          ins: S. Gazdag
        -
          ins: A. Huelsing
        -
          ins: P. Kampanakis
        -
          ins: S. Koelb
        -
          ins: T. Lange
        -
          ins: M. M. Lauridsen
        -
          ins: F. Mendel
        -
          ins: R. Niederhagen
        -
          ins: C. Rechberger
        -
          ins: J. Rijneveld
        -
          ins: P. Schwabe
        -
          ins: B. Westerbaan
      date: 2021-06-10

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
public-key encryption based on CRYSTALS-Kyber, composite public-key signatures
based on CRYSTALS-Dilithium, both in combination with elliptic curve
cryptography, and SPHINCS+ as a standalone public key signature scheme.

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
CRYSTALS-Kyber as a Key Encapsulation Mechanism (KEM), a KEM being a modern
building block for public-key encryption, and CRYSTALS-Dilithium as well as
SPHINCS+ as signature schemes.

For the two CRYSTALS-* schemes, this document follows the conservative strategy
to deploy post-quantum in combination with traditional schemes such that the
security is retained even if all schemes but one in the combination are broken.
In contrast, the hashed-based signature scheme SPHINCS+ is considered to be
sufficiently well understood with respect to its security assumptions in order
to be used standalone. To this end, this document specifies the following new
set: SPHINCS+ standalone and CRYSTALS-* as composite with ECC-based KEM and
digital signature schemes. Here, the term "composite" indicates that any data
structure or algorithm pertaining to the
combination of the two components appears as single data structure or algorithm
from the protocol perspective.

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
on which the two CRYSTALS-* schemes and SPHINCS+ are based, are fundamentally
different, and accordingly the level of trust commonly placed in them as well
as their performance characteristics vary.

\[Note to the reader: This specification refers to the latest NIST submission
papers of each scheme as if it were a specification. This is a temporary
solution that is owed to the fact that currently no other specification is
available. The goal is to provide a sufficiently precise specification of the
algorithms already at the draft stage of this specification, so that it is
possible for implementers to create interoperable implementations. As soon as
standards by NIST or the IETF for the PQC schemes employed in this
specification are available, these will replace the references to the NIST
submission papers. Furthermore, we want to point out that, depending on
possible changes to the schemes standardized by NIST, this specification may be
updated substantially as soon as corresponding information becomes available.\]

### CRYSTALS-Kyber {#kyber-intro}

CRYSTALS-Kyber [Kyber-Subm] is based on the hardness of solving the
learning-with-errors problem in module lattices (MLWE). The scheme is believed
to provide security against cryptanalytic attacks by classical as well as
quantum computers. This specification defines CRYSTALS-Kyber only in composite
combination with ECC-based encryption schemes in order to provide a pre-quantum
security fallback.

### CRYSTALS-Dilithium {#dilithium-intro}

CRYSTALS-Dilithium, defined in [DILITHIUM-Subm], is a signature scheme that,
like CRYSTALS-Kyber, is based on the hardness of solving lattice problems in
module lattices. Accordingly, this specification only defines
CRYSTALS-Dilithium in composite combination with ECC-based signature schemes.

### SPHINCS+

SPHINCS+ [SPHINCS-Subm] is a stateless hash-based signature scheme. Its
security relies on the hardness of finding preimages for cryptographic hash
functions. This feature is generally considered to be a high security
guarantee. Therefore, this specification defines SPHINCS+ as a standalone
signature scheme.

In deployments the performance characteristics of SPHINCS+ should be taken into
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
   of CRYSTALS-Kyber with an ECC-based KEM,

 - PQ/T multi-algorithm digital signature, namely composite combinations of
   CRYSTALS-Dilithium with ECC-based signature schemes,

 - PQ digital signature, namely SPHINCS+ as a standalone cryptographic
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
specification and security advisory mandated from the respective elliptic curve specification.


# Supported Public Key Algorithms

This section specifies the composite Kyber + ECC and Dilithium + ECC schemes as
well as the standalone SPHINCS+ signature scheme. The composite schemes are
fully specified via their algorithm ID. The SPHINCS+ signature schemes are
fully specified by their algorithm ID and an additional parameter ID.

## Algorithm Specifications

For encryption, the following composite KEM schemes are specified:

{: title="KEM algorithm specifications" #kem-alg-specs}
ID | Algorithm                        | Requirement | Definition
--:| -------------------------------- | ----------- | --------------------
29 | Kyber768  + X25519               | MUST        | {{ecc-kyber}}
30 | Kyber1024 + X448                 | SHOULD      | {{ecc-kyber}}
31 | Kyber768  + ECDH-NIST-P-256      | MAY         | {{ecc-kyber}}
32 | Kyber1024 + ECDH-NIST-P-384      | MAY         | {{ecc-kyber}}
33 | Kyber768  + ECDH-brainpoolP256r1 | MAY         | {{ecc-kyber}}
34 | Kyber1024 + ECDH-brainpoolP384r1 | MAY         | {{ecc-kyber}}

For signatures, the following (composite) signature schemes are specified:

{: title="Signature algorithm specifications" #sig-alg-specs}
ID | Algorithm                          | Requirement | Definition
--:| ---------------------------------- | ----------- | --------------------
35 | Dilithium3 + Ed25519               | MUST        | {{ecc-dilithium}}
36 | Dilithium5 + Ed448                 | SHOULD      | {{ecc-dilithium}}
37 | Dilithium3 + ECDSA-NIST-P-256      | MAY         | {{ecc-dilithium}}
38 | Dilithium5 + ECDSA-NIST-P-384      | MAY         | {{ecc-dilithium}}
39 | Dilithium3 + ECDSA-brainpoolP256r1 | MAY         | {{ecc-dilithium}}
40 | Dilithium5 + ECDSA-brainpoolP384r1 | MAY         | {{ecc-dilithium}}
41 | SPHINCS+-simple-SHA2               | SHOULD      | {{sphincs}}
42 | SPHINCS+-simple-SHAKE              | MAY         | {{sphincs}}

## Parameter Specification

### SPHINCS+-simple-SHA2

For the SPHINCS+-simple-SHA2 signature algorithm from {{sig-alg-specs}}, the
following parameters are specified:

{: title="SPHINCS+-simple-SHA2 security parameters" #sphincs-param-sha2}
Parameter ID | Parameter
------------:| -------------------------
1            | SPHINCS+-simple-SHA2-128s
2            | SPHINCS+-simple-SHA2-128f
3            | SPHINCS+-simple-SHA2-192s
4            | SPHINCS+-simple-SHA2-192f
5            | SPHINCS+-simple-SHA2-256s
6            | SPHINCS+-simple-SHA2-256f

All security parameters inherit the requirement of SPHINCS+-simple-SHA2 from
{{sig-alg-specs}}. That is, implementations SHOULD implement the parameters
specified in {{sphincs-param-sha2}}. The values `0x00` and `0xFF` are reserved
for future extensions.

### SPHINCS+-simple-SHAKE

For the SPHINCS+-simple-SHAKE signature algorithm from {{sig-alg-specs}}, the
following parameters are specified:

{: title="SPHINCS+-simple-SHAKE security parameters" #sphincs-param-shake}
Parameter ID | Parameter
------------:| --------------------------
1            | SPHINCS+-simple-SHAKE-128s
2            | SPHINCS+-simple-SHAKE-128f
3            | SPHINCS+-simple-SHAKE-192s
4            | SPHINCS+-simple-SHAKE-192f
5            | SPHINCS+-simple-SHAKE-256s
6            | SPHINCS+-simple-SHAKE-256f

All security parameters inherit the requirement of SPHINCS+-simple-SHAKE from
{{sig-alg-specs}}. That is, implementations MAY implement the parameters
specified in {{sphincs-param-shake}}. The values `0x00` and `0xFF` are reserved
for future extensions.

# Algorithm Combinations

## Composite KEMs

Kyber + ECC public-key encryption is meant to involve both the Kyber KEM and an
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

Dilithium + ECC signatures are meant to contain both the Dilithium and the ECC
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

    (eccCipherText, eccKeyShare) <- eccKem.encap(eccPublicKey)

and

    (eccKeyShare) <- eccKem.decap(eccPrivateKey, eccCipherText)

The placeholder `eccKem` has to be replaced with the specific ECC-KEM from the
row "ECC-KEM" of {{tab-ecdh-cfrg-artifacts}}, {{tab-ecdh-nist-artifacts}}, and
{{tab-ecdh-brainpool-artifacts}}.

#### X25519-KEM {#x25519-kem}

The encapsulation and decapsulation operations of `x25519kem` are described
using the function `X25519()` and encodings defined in [RFC7748]. The
`eccPrivateKey` is denoted as `r`, the `eccPublicKey` as `R`, they are subject
to the equation `R = X25519(r, U(P))`. Here, `U(P)` denotes the u-coordinate of
the base point of Curve25519.

The operation `x25519Kem.encap()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X25519(v,U(P))` where `v`
    is a random scalar

 2. Compute the shared coordinate `X = X25519(v, R)` where `R` is the public key
    `eccPublicKey`

 3. Set the output `eccCipherText` to `V`

 4. Set the output `eccKeyShare` to `SHA3-256(X || eccCipherText || eccPublicKey)`

The operation `x25519Kem.decap()` is defined as follows:

 1. Compute the shared coordinate `X = X25519(r, V)`, where `r` is the
    `eccPrivateKey` and `V` is the `eccCipherText`

 2. Set the output `eccKeyShare` to `SHA3-256(X || eccCipherText || eccPublicKey)`

#### X448-KEM {#x448-kem}

The encapsulation and decapsulation operations of `x448kem` are described using
the function `X448()` and encodings defined in [RFC7748]. The `eccPrivateKey`
is denoted as `r`, the `eccPublicKey` as `R`, they are subject to the equation
`R = X25519(r, U(P))`. Here, `U(P)` denotes the u-coordinate of the base point
of Curve448.

The operation `x448.encap()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V`} via `V = X448(v,U(P))` where `v`
    is a random scalar

 2. Compute the shared coordinate `X = X448(v, R)` where `R` is the public key
    `eccPublicKey`

 3. Set the output `eccCipherText` to `V`

 4. Set the output `eccKeyShare` to `SHA3-512(X || eccCipherText || eccPublicKey)`

The operation `x448Kem.decap()` is defined as follows:

 1. Compute the shared coordinate `X = X448(r, V)`, where `r` is the
    `eccPrivateKey` and `V` is the `eccCipherText`

 2. Set the output `eccKeyShare` to `SHA3-512(X || eccCipherText || eccPublicKey)`

#### ECDH-KEM {#ecdh-kem}

The operation `ecdhKem.encap()` is defined as follows:

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

The operation `ecdhKem.decap()` is defined as follows:

 1. Compute the shared Point `S` as `rV`, where `r` is the `eccPrivateKey` and
    `V` is the `eccCipherText`, according to {{SP800-186}} or {{RFC5639}}

 2. Extract the `X` coordinate from the SEC1 encoded point `S = 04 || X || Y`
    as defined in section {{sec1-format}}

 3. Set the output `eccKeyShare` to `Hash(X || eccCipherText || eccPublicKey)`, with `Hash`
    chosen according to {{tab-ecdh-nist-artifacts}} or
    {{tab-ecdh-brainpool-artifacts}}

### Kyber-KEM {#kyber-kem}

Kyber-KEM features the following operations:

    (kyberCipherText, kyberKeyShare) <- kyberKem.encap(kyberPublicKey)

and

    (kyberKeyShare) <- kyberKem.decap(kyberCipherText, kyberPrivateKey)

The above are the operations Kyber.CCAKEM.Enc() and Kyber.CCAKEM.Dec() defined
in [Kyber-Subm].

Kyber-KEM has the parameterization with the corresponding artifact lengths in
octets as given in {{tab-kyber-artifacts}}. All artifacts are encoded as
defined in [Kyber-Subm].

{: title="Kyber-KEM parameters artifact lengths in octets" #tab-kyber-artifacts}
Algorithm ID reference | Kyber-KEM    | Public key | Secret key | Ciphertext | Key share
----------------------:| ------------ | ---------- | ---------- | ---------- | ---------
29, 31, 33             | kyberKem768  | 1184       | 2400       | 1088       | 32
30, 32, 34             | kyberKem1024 | 1568       | 3186       | 1568       | 32

The placeholder `kyberKem` has to be replaced with the specific Kyber-KEM from
the column "Kyber-KEM" of {{tab-kyber-artifacts}}.

The procedure to perform `kyberKem.encap()` is as follows:

 1. Extract the component public key `kyberPublicKey` that is part of the
    recipient's composite public key

 2. Invoke `(kyberCipherText, keyShare) <- kyberKem.encap(kyberPublicKey)`

 3. Set `kyberCipherText` as the Kyber ciphertext

 4. Set `keyShare` as the Kyber symmetric key share

The procedure to perform `kyberKem.decap()` is as follows:

 1. Invoke `keyShare <-  kyberKem.decap(kyberCipherText, kyberPrivateKey)`

 2. Set `keyShare` as the Kyber symmetric key

## Composite Encryption Schemes with Kyber {#ecc-kyber}

{{kem-alg-specs}} specifies the following Kyber + ECC composite public-key
encryption schemes:

{: title="Kyber-ECC-composite Schemes" #tab-kyber-ecc-composite}
Algorithm ID reference | Kyber-KEM    | ECC-KEM   | ECDH-KEM curve
----------------------:| ------------ | --------- | --------------
29                     | kyberKem768  | x25519Kem | X25519
30                     | kyberKem1024 | x448Kem   | X448
31                     | kyberKem768  | ecdhKem   | NIST P-256
32                     | kyberKem1024 | ecdhKem   | NIST P-384
33                     | kyberKem768  | ecdhKem   | brainpoolP256r1
34                     | kyberKem1024 | ecdhKem   | brainpoolP384r1

The Kyber + ECC composite public-key encryption schemes are built according to
the following principal design:

 - The Kyber-KEM encapsulation algorithm is invoked to create a Kyber
   ciphertext together with a Kyber symmetric key share.

 - The encapsulation algorithm of an ECC-based KEM, namely one out of
   X25519-KEM, X448-KEM, or ECDH-KEM is invoked to create an ECC ciphertext
   together with an ECC symmetric key share.

 - A Key-Encryption-Key (KEK) is computed as the output of a key combiner that
   receives as input both of the above created symmetric key shares and the
   protocol binding information.

 - The session key for content encryption is then wrapped as described in
   {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The v6 PKESK package's algorithm specific parts are made up of the Kyber
   ciphertext, the ECC ciphertext, and the wrapped session key

### Fixed information {#kem-fixed-info}

For the composite KEM schemes defined in {{kem-alg-specs}} the following
procedure, justified in {{sec-fixed-info}}, MUST be used to derive a string to
use as binding between the KEK and the communication parties.

    //   Input:
    //   algID     - the algorithm ID encoded as octet
    //   publicKey - the recipient's encryption sub-key packet
    //               serialized as octet string

    fixedInfo = algID || SHA3-256(publicKey)

SHA3-256 MUST be used to hash the `publicKey` of the recipient.

### Key combiner {#kem-key-combiner}

For the composite KEM schemes defined in {{kem-alg-specs}} the following
procedure MUST be used to compute the KEK that wraps a session key. The
construction is a one-step key derivation function compliant to {{SP800-56C}}
Section 4, based on KMAC256 {{SP800-185}}. It is given by the following
algorithm.

    //   multiKeyCombine(eccKeyShare, eccCipherText,
    //                   kyberKeyShare, kyberCipherText,
    //                   fixedInfo, oBits)
    //
    //   Input:
    //   eccKeyShare     - the ECC key share encoded as an octet string
    //   eccCipherText   - the ECC ciphertext encoded as an octet string
    //   kyberKeyShare   - the Kyber key share encoded as an octet string
    //   kyberCipherText - the Kyber ciphertext encoded as an octet string
    //   fixedInfo       - the fixed information octet string
    //   oBits           - the size of the output keying material in bits
    //
    //   Constants:
    //   domSeparation       - the UTF-8 encoding of the string
    //                         "OpenPGPCompositeKeyDerivationFunction"
    //   counter             - the fixed 4 byte value 0x00000001
    //   customizationString - the UTF-8 encoding of the string "KDF"

    eccKemData = eccKeyShare || eccCipherText
    kyberKemData = kyberKeyShare || kyberCipherText
    encData = counter || eccKemData || kyberKemData || fixedInfo

    MB = KMAC256(domSeparation, encData, oBits, customizationString)

Note that the values `eccKeyShare` defined in {{ecc-kem}} and `kyberKeyShare`
defined in {{kyber-kem}} already use the relative ciphertext in the
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

### Key generation procedure {#ecc-kyber-generation}

The implementation MUST independently generate the Kyber and the ECC component
keys. Kyber key generation follows the specification [KYBER-Subm] and the
artifacts are encoded as fixed-length octet strings. For ECC this is done
following the relative specification in {{RFC7748}}, {{SP800-186}}, or
{{RFC5639}}, and encoding the outputs as fixed-length octet strings in the
format specified in table {{tab-ecdh-cfrg-artifacts}},
{{tab-ecdh-nist-artifacts}}, or {{tab-ecdh-brainpool-artifacts}}.

### Encryption procedure {#ecc-kyber-encryption}

The procedure to perform public-key encryption with a Kyber + ECC composite
scheme is as follows:

 1. Take the recipient's authenticated public-key packet `pkComposite` and
    `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite`

 3. Extract the `eccPublicKey` and `kyberPublicKey` component from the
    algorithm specific data encoded in `pkComposite` with the format specified
    in {{kyber-ecc-key}}.

 4. Instantiate the ECC-KEM `eccKem.encap()` and the Kyber-KEM
    `kyberKem.encap()` depending on the algorithm ID according to
    {{tab-kyber-ecc-composite}}

 5. Compute `(eccCipherText, eccKeyShare) := eccKem.encap(eccPublicKey)`

 6. Compute `(kyberCipherText, kyberKeyShare) :=
    kyberKem.encap(kyberPublicKey)`

 7. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 8. Compute `KEK := multiKeyCombine(eccKeyShare, eccCipherText, kyberKeyShare, kyberCipherText, fixedInfo, oBits=256)` as
    defined in {{kem-key-combiner}}

 9. Compute `C := AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}}
    that includes a 64 bit integrity check

 10. Output `eccCipherText || kyberCipherText || len(C) || C` as specified in
     {{ecc-kyber-pkesk}}

### Decryption procedure

The procedure to perform public-key decryption with a Kyber + ECC composite
scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID and the `encryptedKey`

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `eccSecretKey` and `kyberSecretKey` from the algorithm specific
    data of the own secret key encoded in the format specified in
    {{kyber-ecc-key}}

 5. Instantiate the ECC-KEM `eccKem.decap()` and the Kyber-KEM
    `kyberKem.decap()` depending on the algorithm ID according to
    {{tab-kyber-ecc-composite}}

 6. Parse `eccCipherText`, `kyberCipherText`, and `C` from `encryptedKey`
    encoded as `eccCipherText || kyberCipherText || len(C) || C` as specified
    in {{ecc-kyber-pkesk}}

 7. Compute `(eccKeyShare) := eccKem.decap(eccCipherText, eccPrivateKey)`

 8. Compute `(kyberKeyShare) := kyberKem.decap(kyberCipherText,
    kyberPrivateKey)`

 9. Compute `fixedInfo` as specified in {{kem-fixed-info}}

 10. Compute `KEK := multiKeyCombine(eccKeyShare, eccCipherText, kyberKeyShare, kyberCipherText, fixedInfo, oBits=256)`
     as defined in {{kem-key-combiner}}

 11. Compute `sessionKey := AESKeyUnwrap(KEK, C)`  with AES-256 as per
     {{RFC3394}}, aborting if the 64 bit integrity check fails

 12. Output `sessionKey`

## Packet specifications

### Public-Key Encrypted Session Key Packets (Tag 1) {#ecc-kyber-pkesk}

The composite Kyber algorithms MUST be used only with v6 PKESK, as defined in
[I-D.ietf-openpgp-crypto-refresh] Section 5.1.2.

The algorithm-specific v6 PKESK parameters consists of:

 - A fixed-length octet string representing an ECC ephemeral public key in the
   format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the Kyber ciphertext, whose length depends on
   the algorithm ID as specified in {{tab-kyber-artifacts}}.

 - A variable-length field containing the symmetric key:

   - A one-octet size of the following field;

   - Octet string of the wrapped symmetric key as described in
     {{ecc-kyber-encryption}}.

### Key Material Packets {#kyber-ecc-key}

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an EC point public key, in the
   point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the Kyber public key, whose length
   depends on the algorithm ID as specified in {{tab-kyber-artifacts}}.

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded secret scalar, whose encoding and
   length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the Kyber secret key, whose length
   depends on the algorithm ID as specified in {{tab-kyber-artifacts}}.

# Composite Signature Schemes

## Building blocks

### EdDSA-Based signatures {#eddsa-signature}

To sign and verify with EdDSA the following operations are defined:

    (eddsaSignature) <- eddsa.sign(eddsaPrivateKey, dataDigest)

and

    (verified) <- eddsa.verify(eddsaPublicKey, eddsaSignature, dataDigest)

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

    (ecdsaSignatureR, ecdsaSignatureS) <- ecdsa.sign(ecdsaPrivateKey,
                                                     dataDigest)

and

    (verified) <- ecdsa.verify(ecdsaPublicKey, ecdsaSignatureR,
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

### Dilithium signatures {#dilithium-signature}

The procedure for Dilithium signature generation is the function `Sign(sk, M)`
given in Figure 4 in [DILITHIUM-Subm], where `sk` is the Dilithium private key
and `M` is the data to be signed. OpenPGP does not use the optional randomized
signing given as a variant in the definition of this function, i.e. `rho' :=
H(K || mu)` is used. The signing function returns the Dilithium signature. That
is, to sign with Dilithium the following operation is defined:

    (dilithiumSignature) <- dilithium.sign(dilithiumPrivateKey,
                                           dataDigest)

The procedure for Dilithium signature verification is the function `Verify(pk,
M, sigma)` given in Figure 4 in [DILITHIUM-Subm], where `pk` is the Dilithium
public key, `M` is the data to be signed and `sigma` is the Dilithium
signature. That is, to verify with Dilithium the following operation is
defined:

    (verified) <- dilithium.verify(dilithiumPublicKey, dataDigest,
                                   dilithiumSignature)

Dilithium has the parameterization with the corresponding artifact lengths in
octets as given in {{tab-dilithium-artifacts}}. All artifacts are encoded as
defined in [Dilithium-Subm].

{: title="Dilithium parameters and artifact lengths in octets" #tab-dilithium-artifacts}
Algorithm ID reference | Dilithium instance | Public key | Secret key | Signature value
----------------------:| ------------------ | -----------| ---------- | ---------------
35, 37, 39             | Dilithium3         | 1952       | 4000       | 3293
36, 38, 40             | Dilithium5         | 2592       | 4864       | 4595

## Composite Signature Schemes with Dilithium {#ecc-dilithium}

### Binding hashes

Composite Dilithium + ECC signatures MUST use SHA3-256 (hash algorithm ID 12)
or SHA3-512 (hash algorithm ID 14) as hashing algorithm. Signatures using other
hash algorithms MUST be considered invalid.

An implementation MUST support SHA3-256 and SHOULD support SHA3-512, in
order to support the hash binding with Dilithium + ECC signatures.

### Key generation procedure {#ecc-dilithium-generation}

The implementation MUST independently generate the Dilithium and the ECC
component keys. Dilithium key generation follows the specification in
[DILITHIUM-Subm] and the artifacts are encoded as fixed-length octet strings as
defined in {{dilithium-signature}}. For ECC this is done following the relative
specification in {{RFC7748}}, {{SP800-186}}, or {{RFC5639}}, and encoding the
artifacts as specified in {{eddsa-signature}} or {{ecdsa-signature}} as
fixed-length octet strings.

### Signature Generation

To sign a message `M` with Dilithium + EdDSA the following sequence of
operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}}
    Section 5.2.4

 2. Create the EdDSA signature over `dataDigest` with `eddsa.sign()` from
    {{eddsa-signature}}

 3. Create the Dilithium signature over `dataDigest` with `dilithium.sign()`
    from {{dilithium-signature}}

 4. Encode the EdDSA and Dilithium signatures according to the packet
    structure given in {{ecc-dilithium-sig-packet}}.

To sign a message `M` with Dilithium + ECDSA the following sequence of
operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}}
    Section 5.2.4

 2. Create the ECDSA signature over `dataDigest` with `ecdsa.sign()` from
    {{ecdsa-signature}}

 3. Create the Dilithium signature over `dataDigest` with `dilithium.sign()`
    from {{dilithium-signature}}

 4. Encode the ECDSA and Dilithium signatures according to the packet
    structure given in {{ecc-dilithium-sig-packet}}.

### Signature Verification

To verify a Dilithium + EdDSA signature the following sequence of operations
has to be performed:

 1. Verify the EdDSA signature with `eddsa.verify()` from {{eddsa-signature}}

 2. Verify the Dilithium signature with `dilithium.verify()` from
    {{dilithium-signature}}

To verify a Dilithium + ECDSA signature the following sequence of operations
has to be performed:

 1. Verify the ECDSA signature with `ecdsa.verify()` from {{ecdsa-signature}}

 2. Verify the Dilithium signature with `dilithium.verify()` from
    {{dilithium-signature}}

As specified in {{composite-signatures}} an implementation MUST validate both
signatures, i.e. EdDSA/ECDSA and Dilithium, to state that a composite Dilithium
+ ECC signature is valid.

## Packet Specifications

### Signature Packet (Tag 2) {#ecc-dilithium-sig-packet}

The composite Dilithium + ECC schemes MUST be used only with v6 signatures, as
defined in [I-D.ietf-openpgp-crypto-refresh] Section 5.2.3.

The algorithm-specific v6 signature parameters for Dilithium + EdDSA signatures
consists of:

 - A fixed-length octet string representing the EdDSA signature, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string of the Dilithium signature value, whose length
   depends on the algorithm ID as specified in {{tab-dilithium-artifacts}}.

The algorithm-specific v6 signature parameters for Dilithium + ECDSA signatures
consists of:

 - A fixed-length octet string of the big-endian encoded ECDSA value `R`, whose
   length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the big-endian encoded ECDSA value `S`, whose
   length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the Dilithium signature value, whose length
   depends on the algorithm ID as specified in {{tab-dilithium-artifacts}}.

### Key Material Packets

The composite Dilithium + ECC schemes MUST be used only with v6 keys, as
defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key for Dilithium + EdDSA keys is this series of
values:

 - A fixed-length octet string representing the EdDSA public key, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the Dilithium public key, whose
   length depends on the algorithm ID as specified in
   {{tab-dilithium-artifacts}}.

The algorithm-specific private key for Dilithium + EdDSA keys is this series of
values:

 - A fixed-length octet string representing the EdDSA secret key, whose length
   depends on the algorithm ID as specified in {{tab-eddsa-artifacts}}.

 - A fixed-length octet string containing the Dilithium secret key, whose
   length depends on the algorithm ID as specified in
   {{tab-dilithium-artifacts}}.

The algorithm-specific public key for Dilithium + ECDSA keys is this
series of values:

 - A fixed-length octet string representing the ECDSA public key in SEC1
   format, as specified in section {{sec1-format}} and with length specified in
   {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the Dilithium public key, whose
   length depends on the algorithm ID as specified in
   {{tab-dilithium-artifacts}}.

The algorithm-specific private key for Dilithium + ECDSA keys is this series of
values:

 - A fixed-length octet string representing the ECDSA secret key as a
   big-endian encoded integer, whose length depends on the algorithm used as
   specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the Dilithium secret key, whose
   length depends on the algorithm ID as specified in
   {{tab-dilithium-artifacts}}.

# SPHINCS+

## The SPHINCS+ Algorithms {#algo-sphincs}

The following table describes the SPHINCS+ parameters and artifact lengths:

{: title="SPHINCS+ parameters and artifact lengths in octets. The values equally apply to the parameter IDs of SPHINCS+-simple-SHA2 and SPHINCS+-simple-SHAKE." #sphincs-artifact-lengths}
Parameter ID reference | Parameter name suffix | SPHINCS+ public key | SPHINCS+ secret key | SPHINCS+ signature
----------------------:| ---------------------:| ------------------- | ------------------- | ------------------
1                      | 128s                  | 32                  | 64                  | 7856
2                      | 128f                  | 32                  | 64                  | 17088
3                      | 192s                  | 48                  | 96                  | 16224
4                      | 192f                  | 48                  | 96                  | 35664
5                      | 256s                  | 64                  | 128                 | 29792
6                      | 256f                  | 64                  | 128                 | 49856

### Binding hashes

SPHINCS+ signature packets MUST use the associated hash as specified in
{{tab-sphincs-hash}}. Signature packets using other hashes MUST be considered
invalid.

{: title="Binding between SPHINCS+ and signature hashes" #tab-sphincs-hash}
Algorithm ID reference | Parameter ID reference | Hash function | Hash function ID reference
----------------------:| ---------------------- | ------------- | --------------------------
41                     | 1, 2                   | SHA-256       | 8
41                     | 3, 4, 5, 6             | SHA-512       | 10
42                     | 1, 2                   | SHA3-256      | 12
42                     | 3, 4, 5, 6             | SHA3-512      | 14

An implementation supporting a specific SPHINCS+ algorithm and parameter MUST
also support the matching hash algorithm.

### Key generation

The SPHINCS+ key generation is performed according to the function
`spx_keygen()` specified in {{SPHINCS-Subm}}, Sec. 6.2 as Alg. 19. The private
and public key are encoded as defined in {{SPHINCS-Subm}}.

### Signature Generation

The procedure for SPHINCS+ signature generation is the function `spx_sign(M,
SK)` specified in {{SPHINCS-Subm}}, Sec. 6.4 as Alg. 20.  Here, `M` is the
`dataDigest` generated according to {{I-D.ietf-openpgp-crypto-refresh}} Section
5.2.4 and `SK` is the SPHINCS+ private key. The global variable `RANDOMIZE`
specified in Alg. 20 is to be considered as not set, i.e. the variable `opt`
shall be initialized with `PK.seed`. See also {{sphincs-sec-cons}}.

An implementation MUST set the Parameter ID in the signature equal to the
issuing private key Parameter ID.

### Signature Verification

The procedure for SPHINCS+ signature verification is the function
`spx_verify(M, SIG, PK)` specified in {{SPHINCS-Subm}}, Sec. 6.5 as Alg. 21.
Here, `M` is the `dataDigest` generated according to
{{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4, `SIG` is the signature, and
`PK` is the SPHINCS+ public key.

An implementation MUST check that the Parameter ID in the signature and in the
key match when verifying.

## Packet specifications

###  Signature Packet (Tag 2)

The SPHINCS+ algorithms MUST be used only with v6 signatures, as defined in
[I-D.ietf-openpgp-crypto-refresh] Section 5.2.3.

The algorithm-specific v6 Signature parameters consists of:

 - A one-octet value specifying the SPHINCS+ parameter ID defined in
   {{sphincs-param-sha2}} and {{sphincs-param-shake}}. The values `0x00` and
   `0xFF` are reserved for future extensions.

 - A fixed-length octet string of the SPHINCS+ signature value, whose length
   depends on the parameter ID in the format specified in
   {{sphincs-artifact-lengths}}.

### Key Material Packets

The SPHINCS+ algorithms MUST be used only with v6 keys, as defined in
[I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key is this series of values:

 - A one-octet value specifying the SPHINCS+ parameter ID defined in
   {{sphincs-param-sha2}} and {{sphincs-param-shake}}. The values `0x00` and
   `0xFF` are reserved for future extensions.

 - A fixed-length octet string containing the SPHINCS+ public key, whose length
   depends on the parameter ID as specified in {{sphincs-artifact-lengths}}.

The algorithm-specific private key is this value:

 - A fixed-length octet string containing the SPHINCS+ secret key, whose length
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
of all artifacts, including the derived key. The hash of the recipient's
public key identifies the subkey used to encrypt the message, binding the KEK
to both the Kyber and the ECC key. Given that both algorithms allow a degree of
ciphertext malleability, this prevents transformations onto the ciphertext
without the final recipient's knowledge.

This is in line with the Recommendation for ECC in section 5.5 of
[SP800-56A]. Other fields included in the recommendation are not relevant
for the OpenPGP protocol, since the sender is not required to have a key on
their own, there are no pre-shared secrets, and all the other parameters are
univocally defined by the algorithm ID.

## SPHINCS+ {#sphincs-sec-cons}

The original specification of SPHINCS+ {{SPHINCS-Subm}} prescribes an optional
randomized hashing. This is not used in this specification, as OpenPGP v6
signatures already provide a salted hash of the appropriate size.

## Binding hashes in signatures with signature algorithms

In order not to extend the attack surface, we bind the hash algorithm used for
message digestion to the hash algorithm used internally by the signature
algorithm. Dilithium internally uses a SHAKE256 digest, therefore we require
SHA3 in the Dilithium + ECC signature packet. In the case of SPHINCS+ the
internal hash algorithm varies based on the algorithm and parameter ID.


# Additional considerations

## Performance Considerations for SPHINCS+ {#performance-considerations}

This specification introduces both Dilithium + ECC as well as SPHINCS+ as
PQ(/T) signature schemes.

Generally, it can be said that Dilithium + ECC provides a performance in terms
of execution time and space requirements that is close to that of traditional
ECC signature schemes. Implementers may want to offer SPHINCS+ for applications
where a higher degree of trust in the signature scheme is required. However,
SPHINCS+ has performance characteristics in terms of execution time of the
signature generation as well as space requirements for the signature that can
be, depending on the parameter choice, far greater than those of traditional or
Dilithium + ECC signature schemes.

Pertaining to the execution time, the particularly costly operation in SPHINCS+
is the signature generation. In order to achieve short signature generation
times, one of the parameter sets with the name ending in the letter "f" for
"fast" should be chosen. This comes at the expense of a larger signature size.

In order to minimize the space requirements of a SPHINCS+ signature, a
parameter set ending in "s" for "small" should be chosen. This comes at the
expense of a larger signature generation time.

# IANA Considerations

IANA will add the following registries to the `Pretty Good Privacy (PGP)`
registry group at https://www.iana.org/assignments/pgp-parameters:

- Registry name: `SPHINCS+-simple-SHA2 parameters`

  Registration procedure: SPECIFICATION REQUIRED [RFC8126]

  Values defined in this document, {{sphincs-param-sha2}}.

- Registry name: `SPHINCS+-simple-SHAKE parameters`

  Registration procedure: SPECIFICATION REQUIRED [RFC8126]

  Values defined in this document, {{sphincs-param-shake}}.

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
