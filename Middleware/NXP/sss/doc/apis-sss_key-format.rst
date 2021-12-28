..
    Copyright 2019,2020 NXP

    SPDX-License-Identifier: Apache-2.0

.. _apis-sss_key-format:

======================================================================
 SSS api key format (asymmetric keys)
======================================================================


NIST-P, NIST-K and BRAINPOOL ECC Keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using PKCS #8 or traditional openssl format.
When passing the private key alone, do not include the key header.

When retrieving the key pair as data argument from the sss_key_store_get api, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.

.. note:: Keys, signature and shared secret key generated all follow the big endian convention.


EDWARD and MONTGOMERY ECC keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using the format specified in RFC 8410.
When passing the private key alone, do not include the key header.

When retrieving the key pair as data argument from the sss_key_store_get api, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.

.. note:: Keys, signature and shared secret key generated all follow the little endian convention.

A set of examples of a X25519 keypair encoded according to RFC 8410::

  $ dumpasn1 X25519_keypair.der
   0  81: SEQUENCE {
   2   1:   INTEGER 1
   5   5:   SEQUENCE {
   7   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
        :     }
  12  34:   OCTET STRING, encapsulates {
  14  32:     OCTET STRING
        :       58 5D B1 E3 50 0B 71 24 F6 B1 E1 41 83 54 93 12
        :       F4 4B 0C A3 44 F7 52 A1 8A 12 2F E7 DA D9 CE 52
        :     }
  48  33:   [1]
        :     00 A2 8E 04 FF 1C DC 1C 3D 60 91 0F BC 98 EF 01
        :     BF 9F 0F 69 C0 B7 EF 70 61 35 34 62 F3 06 28 C7
        :     29
        :   }

  $ dumpasn1 X25519_priv.pem
    0  46: SEQUENCE {
    2   1:   INTEGER 0
    5   5:   SEQUENCE {
    7   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
         :     }
   12  34:   OCTET STRING, encapsulates {
   14  32:     OCTET STRING
         :       58 5D B1 E3 50 0B 71 24 F6 B1 E1 41 83 54 93 12
         :       F4 4B 0C A3 44 F7 52 A1 8A 12 2F E7 DA D9 CE 52
         :     }
         :   }

  $ dumpasn1 X25519_pub.pem
    0  42: SEQUENCE {
    2   5:   SEQUENCE {
    4   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
         :     }
    9  33:   BIT STRING
         :     A2 8E 04 FF 1C DC 1C 3D 60 91 0F BC 98 EF 01 BF
         :     9F 0F 69 C0 B7 EF 70 61 35 34 62 F3 06 28 C7 29
         :   }


The X25519 keypair from the example above can be created with the asn1parse OpenSSL tool.
The command line invocation is as follows::

  openssl asn1parse -genconf key_config.txt -out X25519_keypair.der

The file **key_config.txt** contains the different ASN.1 components and values of the keypair to create.
The resulting DER representation of the keypair is stored in the file  **X25519_keypair.der**.
The contents of the **key_config.txt** file is as follows::
  
  asn1 = SEQUENCE:seq_section
  
  [seq_section]
  
  field1 = INTEGER:1
  field2 = SEQUENCE:seq_section_oid
  field3 = OCTWRAP,FORMAT:HEX,OCT:585DB1E3500B7124F6B1E14183549312F44B0CA344F752A18A122FE7DAD9CE52
  field4 = IMP:1C,INT:0x00A28E04FF1CDC1C3D60910FBC98EF01BF9F0F69C0B7EF7061353462F30628C729
  
  [seq_section_oid]
  
  field1 = OID:X25519

.. note:: Additional information on the *asn1parse* command and the key configuration format is available under the manpages of respectively *asn1parse* and *ASN1_generate_nconf*

BN Curve ECC keys
======================================================================
When passing key pair, private key or public key do not include key header.
When retrieving the key from the sss_key_store_get api, the public key value is returned without any header.


RSA keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using PKCS #8 or traditional openssl format.
When passing the private key alone, do not include the key header.

When retrieving the key pair as data argument from the sss_key_store_get API, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.
