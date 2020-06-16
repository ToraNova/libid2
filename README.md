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
The deprecated version of the library found under the deprecate directory supports 3 schemes. This renewed version currently only supports 2.

#### Using Ristretto Curve25519
	1. TNC-Schnorr IBI
	2. CLI (Certificateless Identification)
	3. Schnorr IBI
	4. Tight Schnorr

### Supported Signature Schemes
Likewise, the deprecated version supports 3 schemes while the renewed currently only supports 1.

#### Using Ristretto Curve25519
	1. TNC-Schnorr
	2. Schnorr
	3. Tight-Schnorr
