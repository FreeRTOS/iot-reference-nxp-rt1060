# OpenSSL A71CH Legacy engine

Starting with OpenSSL 0.9.6 an ‘Engine interface’ was added allowing support for alternative cryptographic implementations.
This Engine interface can be used to interface with external crypto devices.
The key injection process is secure module specific and is not covered by the Engine interface.

## Key Management
The cryptographic functionality offered by the openssl a71ch legacy engine requires a reference to a key stored inside the Secure Element (exception is RAND_Method).
These keys are typically inserted into the Secure Element in a secured environment during production.
OpenSSL requires a key pair, consisting of a private and a public key, to be loaded before the cryptographic operations can be executed. This creates a challenge when OpenSSL is used in combination with a secure element as the private key cannot be extracted out from the Secure Element.
The solution is to populate the OpenSSL Key data structure with only a reference to the Private Key inside the Secure Element instead of the actual Private Key. The public key as read from the Secure Element can still be inserted into the key structure. OpenSSL crypto API’s are then invoked with these data structure objects as parameters. When the crypto API is routed to the Engine, the openssl engine implementation decodes these key references and invokes the Host API with correct Key references for a cryptographic operation.

### EC Reference key format
The following provides an example of an EC reference key. The value reserved for the private key
has been used to contain:
- a pattern of `0x10..00` to fill up the datastructure MSB side to the desired key length
- a 32 bit key identifier (in the example below `0x7DCCBBAA`)
- a 64 bit magic number (always `0xA5A6B5B6A5A6B5B6`)
- a byte to describe the key class (use a reserved value `0x00` in case of SE050)
- a byte to describe the key index (use a reserved value `0x00` in case of SE050)

```text
    Private-Key: (256 bit)
    priv:
        10:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
        00:00:00:7D:CC:BB:AA:A5:A6:B5:B6:A5:A6:B5:B6:
        kk:ii
    pub:
        04:1C:93:08:8B:26:27:BA:EA:03:D1:BE:DB:1B:DF:
        8E:CC:87:EF:95:D2:9D:FC:FC:3A:82:6F:C6:E1:70:
        A0:50:D4:B7:1F:F2:A3:EC:F8:92:17:41:60:48:74:
        F2:DB:3D:B4:BC:2B:F8:FA:E8:54:72:F6:72:74:8C:
        9E:5F:D3:D6:D4
    ASN1 OID: prime256v1
```

\note The key identifier 0x7DCCBBAA (stored in big-endian convention) is in front of the magic number 0xA5A6B5B6A5A6B5B6

\note The padding of the private key value and the magic number make it unlikely a normal private key value matches a reference key.

\note Ensure the value reserved for public key and ASN1 OID contain the values matching the stored key.

### Building the OpenSSL a71ch legacy engine
The cmake build system will create an OpenSSL a71ch legacy engine for supported platforms.
The resulting OpenSSL engine will be copied to the SW tree in directory
``simw-top/hostlib/hostLib/embSeEngine/bin``

### Validating the OpenSSL a71ch legacy engine
This directory contains validation/test scripts for the SSS_OpenSSL a71ch legacy engine.
Before executing these scripts, the secure element must first be provisioned.

#### On iMX with A71CH connected via I2C
Execute these python scripts from a command shell on the iMX

(1) First provision the attached A71CH

    python3 legacy_openssl_provision.py sci2c none


(2) Next run the following validation scripts

```bat
    # Does not require prior provisioning
    python3 legacy_openssl_rnd.py none
    # Requires prior provisioning
    python3 legacy_openssl_Ecdh.py none
    python3 legacy_openssl_EccSign.py none
```    

#### From a PC connecting to a JRCP_v1 server

(1) Assuming a JRCP_v1 server (aka RJCT server) is available on address ``192.168.2.75:8050``, execute

    python legacy_openssl_provision.py jrcpv1 192.168.2.75:8050


(2) Run the following validation scripts (choose ip_address:port as appropriate)

```bat
    # Does not require prior provisioning
    python legacy_openssl_rnd.py 192.168.2.75:8050
    # Requires prior provisioning
    python legacy_openssl_Ecdh.py 192.168.2.75:8050
    python legacy_openssl_EccSign.py 192.168.2.75:8050
```
