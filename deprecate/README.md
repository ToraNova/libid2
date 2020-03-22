# id2 - An Identity-based Identification library
id2 is a library to deploy an identity-based identification (ibi) scheme a computer system/network. In contrast to conventional public-key cryptosystems,
the public key for id-based systems is the id of an entity itself, thereby eliminating the need for a trusted third party.

## Dependencies
id2 uses the following external libraries:
1. [pbc library](https://crypto.stanford.edu/pbc/)
2. [NaCL](https://nacl.cr.yp.to/)

## Supported IBI Schemes
id2 currently supports 2 schemes:
1. Tight-BLS IBI
2. TNC-Schnorr IBI (using Curve25519)
3. BLS-IBI

### Supported Signature Schemes
Signature schemes are basis for IBI schemes, id2 also supports the following signature schemes:
1. BLS signatures
2. TNC-Schnorr signatures
3. Tight-BLS signatures
