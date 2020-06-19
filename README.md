# libid2 - identity-based identification library
id2 is a library for identity-based identification (ibi) for systems requiring authentication. In contrast to conventional public-key cryptosystems, the public key for id-based systems is the id of an entity itself, thereby eliminating the need for a trusted third party and storage of certificates.

# Dependencies
id2 uses the following external libraries:
1. [NaCL](https://nacl.cr.yp.to/)

## Compile
To compile, ensure autotools such as `automake`, `autoconf` and `libtool` are installed.
```
pacman -S gcc make automake autoconf libtool
git clone https://github.com/toranova/id2 && cd id2
autoreconf --install && mkdir build && cd build && ../configure
make
```
To install, run following with sufficient privileges (i.e., using su or sudo)
```
make install
```
To compile and test with debugging
```
cd debug && ../configure --prefix=/debug
```
OR
```
../configure CPPFLAGS="-DDEBUG" CFLAGS="-DDEBUG -g -O0"
```

### Supported IBI Schemes
The latest version supports 7 identity-based identification schemes. The deprecated version supports an [IBI using BLS signatures](https://ieeexplore.ieee.org/document/9049156)

#### Using Ristretto Curve25519
0. TNC-Schnorr IBI
1. CLI (Certificateless Identification)
2. Schnorr-IBI
3. [Tight-Schnorr](https://www.researchgate.net/publication/221317622_A_Variant_of_Schnorr_Identity-Based_Identification_Scheme_with_Tight_Reduction)
4. [Twin-Schnorr](https://www.hindawi.com/journals/tswj/2015/237514/)
5. [Reset-secure Schnorr](https://www.researchgate.net/publication/286842222_Reset-Secure_Identity-Based_Identification_Schemes_Without_Pairings)
6. [Reset-secure Twin-Schnorr](https://www.researchgate.net/publication/286842222_Reset-Secure_Identity-Based_Identification_Schemes_Without_Pairings)

### Supported Signature Schemes
The latest version supports 2 signature schemes, TNC-Schnorr and Schnorr signatures on Ristretto25519. The deprecated version supports BLS signatures based on TightBLS using libpbc.

#### Using Ristretto Curve25519
0. TNC-Schnorr
1. Schnorr
