These are preliminary test vectors for public-key encrypted packets using kyber768-x25519.
dilithium3-ed25519 signatures are also contained since it's the primary key that is used for key signatures etc.
This corresponds to the crypto refresh version at commit bccb45aa and draft-wussler-openpgp-pqc-01.
There might be issues with the v6 format, e.g., missing subpackets/features but otherwise this should be correct data and be parsable / decryptable.

# Rudimentary Dumps of the files

### dilithium3-ed25519-with-kyber768-x25519-pubkey.asc

```
:off 0: packet header 0xc6c70a (tag 6, len 1994)
Public key packet
    version: 6
    creation time: 1685007815 (Thu May 25 11:43:35 2023)
    public key algorithm: 35 (Dilithium3 + ED25519)
    public key material:
        dilithium-ecdsa/eddsa encodced pubkey
    keyid: 0x699256cc0599736b
:off 1997: packet header 0xcd31 (tag 13, len 49)
UserID packet
    id: Dilithium-ED25519 15872-bit key <jroth@localhost>
:off 2048: packet header 0xc2ccbf (tag 2, len 3455)
Signature packet
    version: 6
    type: 19 (Positive User ID certification)
    public key algorithm: 35 (Dilithium3 + ED25519)
    hash algorithm: 8 (SHA256)
    hashed subpackets:
        :type 33, len 33
        issuer fingerprint: 0x730160ba699812a9f6728e6b69f7efa9424e8d6fd9ce75ad699256cc0599736b (32 bytes)
        :type 2, len 4
        signature creation time: 1685007815 (Thu May 25 11:43:35 2023)
        :type 9, len 4
        key expiration time: 63072000 seconds (730 days)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 11, len 3
        preferred symmetric algorithms: AES-256, AES-192, AES-128 (9, 8, 7)
        :type 21, len 4
        preferred hash algorithms: SHA256, SHA384, SHA512, SHA224 (8, 9, 10, 11)
        :type 22, len 4
        preferred compression algorithms: ZLib, BZip2, ZIP, Uncompressed (2, 3, 1, 0)
    unhashed subpackets:
        none
    lbits: 0x8b27
    signature material:
        dilithium-ecdsa/eddsa sig
:off 5506: packet header 0xcec40a (tag 14, len 1226)
Public subkey packet
    version: 6
    creation time: 1685007815 (Thu May 25 11:43:35 2023)
    public key algorithm: 29 (Kyber768 + X25519)
    public key material:
        kyber-ecdh encoded pubkey
    keyid: 0x8ce1b1f9c11490e1
:off 6735: packet header 0xc2ccae (tag 2, len 3438)
Signature packet
    version: 6
    type: 24 (Subkey Binding Signature)
    public key algorithm: 35 (Dilithium3 + ED25519)
    hash algorithm: 8 (SHA256)
    hashed subpackets:
        :type 33, len 33
        issuer fingerprint: 0x730160ba699812a9f6728e6b69f7efa9424e8d6fd9ce75ad699256cc0599736b (32 bytes)
        :type 2, len 4
        signature creation time: 1685007815 (Thu May 25 11:43:35 2023)
        :type 9, len 4
        key expiration time: 63072000 seconds (730 days)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
    unhashed subpackets:
        none
    lbits: 0xbbbf
    signature material:
        dilithium-ecdsa/eddsa sig
```

### dilithium3-ed25519-with-kyber768-x25519-seckey.asc

```
:off 0: packet header 0xc5d6cb (tag 5, len 6027)
Secret key packet
    version: 6
    creation time: 1685007815 (Thu May 25 11:43:35 2023)
    public key algorithm: 35 (Dilithium3 + ED25519)
    public key material:
        dilithium-ecdsa/eddsa encodced pubkey
    secret key material:
        s2k usage: 0
        cleartext secret key data: 4032 bytes
    keyid: 0x699256cc0599736b
:off 6030: packet header 0xcd31 (tag 13, len 49)
UserID packet
    id: Dilithium-ED25519 15872-bit key <jroth@localhost>
:off 6081: packet header 0xc2ccbf (tag 2, len 3455)
Signature packet
    version: 6
    type: 19 (Positive User ID certification)
    public key algorithm: 35 (Dilithium3 + ED25519)
    hash algorithm: 8 (SHA256)
    hashed subpackets:
        :type 33, len 33
        issuer fingerprint: 0x730160ba699812a9f6728e6b69f7efa9424e8d6fd9ce75ad699256cc0599736b (32 bytes)
        :type 2, len 4
        signature creation time: 1685007815 (Thu May 25 11:43:35 2023)
        :type 9, len 4
        key expiration time: 63072000 seconds (730 days)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 11, len 3
        preferred symmetric algorithms: AES-256, AES-192, AES-128 (9, 8, 7)
        :type 21, len 4
        preferred hash algorithms: SHA256, SHA384, SHA512, SHA224 (8, 9, 10, 11)
        :type 22, len 4
        preferred compression algorithms: ZLib, BZip2, ZIP, Uncompressed (2, 3, 1, 0)
    unhashed subpackets:
        none
    lbits: 0x8b27
    signature material:
        dilithium-ecdsa/eddsa sig
:off 9539: packet header 0xc7cd8b (tag 7, len 3659)
Secret subkey packet
    version: 6
    creation time: 1685007815 (Thu May 25 11:43:35 2023)
    public key algorithm: 29 (Kyber768 + X25519)
    public key material:
        kyber-ecdh encoded pubkey
    secret key material:
        s2k usage: 0
        cleartext secret key data: 2432 bytes
    keyid: 0x8ce1b1f9c11490e1
:off 13201: packet header 0xc2ccae (tag 2, len 3438)
Signature packet
    version: 6
    type: 24 (Subkey Binding Signature)
    public key algorithm: 35 (Dilithium3 + ED25519)
    hash algorithm: 8 (SHA256)
    hashed subpackets:
        :type 33, len 33
        issuer fingerprint: 0x730160ba699812a9f6728e6b69f7efa9424e8d6fd9ce75ad699256cc0599736b (32 bytes)
        :type 2, len 4
        signature creation time: 1685007815 (Thu May 25 11:43:35 2023)
        :type 9, len 4
        key expiration time: 63072000 seconds (730 days)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
    unhashed subpackets:
        none
    lbits: 0xbbbf
    signature material:
        dilithium-ecdsa/eddsa sig
```

### pkesk-seipdv2-kyber768-x25519.asc

```
:off 0: packet header 0xc1c3ed (tag 1, len 1197)
Public-key encrypted session key packet
    version: 6
    fingerprint: 0xd4ae3e75cdf60da4ac91549e38584cefb365ce0005e75af78ce1b1f9c11490e1 (32 bytes)
    public key algorithm: 29 (Kyber768 + X25519)
    encrypted material:
        kyber-ecdh composite ciphertext
        kyber-ecdh wrapped session key
:off 1200: packet header 0xd264 (tag 18, len 100)
Symmetrically-encrypted integrity protected data packet
```
