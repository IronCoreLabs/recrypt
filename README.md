Recrypt
==========================
[![Build Status](https://travis-ci.org/IronCoreLabs/recrypt.svg?branch=master)](https://travis-ci.org/IronCoreLabs/recrypt)
[![codecov.io](https://codecov.io/github/IronCoreLabs/recrypt/coverage.svg?branch=master)](https://codecov.io/github/IronCoreLabs/recrypt?branch=master)
[![scaladoc](https://javadoc-badge.appspot.com/com.ironcorelabs/recrypt-core_2.12.svg?label=scaladoc)](https://javadoc-badge.appspot.com/com.ironcorelabs/recrypt-core_2.12)
[![NPM Version](https://badge.fury.io/js/%40ironcorelabs%2Frecryptjs.svg)](https://www.npmjs.com/package/@ironcorelabs/recryptjs)

This is a library that implements a set of cryptographic primitives that are needed for a _multi-hop proxy re-encryption_ scheme.

The library is implemented in Scala, and the build produces a `.jar` you can use with Java applications. It also cross-compiles to Javascript, so you can use the library in web applications to add end-to-end encryption.

# Proxy Re-Encryption

A proxy re-encryption (PRE) scheme is a public-key encryption scheme, meaning that each participant has a pair of related keys, one public and one private. If Alice wants to encrypt a message so that only Bob can read it, she obtains Bob's public key and uses the public key encryption algorithm to secure the message. When Bob receives the encrypted message, he uses his private key to decrypt it and recover the original message.

PRE allows someone (the _delegator_) to delegate the ability to decrypt her messages to another person (the _delegatee_). In a standard public-key cryptosystem, the delegator would just need to share her private key with the delegatee. This allows the delegatee to access the encrypted messages, but when the delegator wants to revoke the access, she cannot be absolutely sure the delegatee will discard his copy of the private key. With proxy re-encryption, the delegator computes a _re-encryption key_ (or _transform key_) that will allow messages encrypted to her public key to be transformed so they are encrypted to the delegatee's public key. Computing this transform key requires the delegator's private key and the delegatee's public key; once it is computed, the key is stored on a _semi-trusted proxy_.

The proxy receives messages intended for the delegator, applies the transform algorithm using the transform key, and delivers the transformed message to the delegatee. __The proxy does not need to be trusted, because possession of the transform key does not allow the proxy to recover any information about either the delegator's or the delegatee's private keys.__ The delegatee cannot collaborate with proxy to recover any information about the delegator's private key.

When the delegator no longer wants to delegate access, she just requests that the proxy discard the transform key. She must trust the proxy to perform this action.

### PRE Scheme Properties

There are a number of ways to categorize PRE schemes; some of the most important are the following:

- _Directionality_ describes whether delegate from A to B also allows transformation from B to A. Unidirectional schemes do not allow this.
- _Interactivity_ describes whether both parties must be actively involved in order to generate the transform key. A non-interactive scheme only requires the public key of the delegatee.
- _Transitivity_ describes whether a proxy can re-delegate encryption. That is, if the proxy holds a transform key from A to B and a transform key from B to C, can it generate a transform key from a to C? A non-transitive scheme does not allow this.
- _Collusion safety_ describes whether it is possible for a delegatee to collude with the proxy that holds a transform key to that delegatee in order to recover the private key of the delegator. A collusion-safe scheme does not allow this.
- _Multi-hop_ describes whether it is possible to allow a delegatee to also be a delegator. That is, does the scheme allow a ciphertext that has already been transformed from Alice to Bob to subsequently be transformed from Bob to Carol. In a multi-hop situation, the proxies would cahin the transformations, so any delegatee in the chain could decrypt any message that one of her delegators could decrypt.

The Recrypt library implements a PRE scheme that is unidirectional, non-interactive, non-transitive, collusion-safe, and multi-hop.

## Cryptographic Primitives

The Recrypt library provides the following cryptographic primitives that are part of the proxy re-encryption scheme:

- `generateKeyPair`: generate a public/private key pair for the caller. The private key is chosen randomly
- `generateTransformKey`: given a delegator's private key and a delegatee's public key, generate the transform key
- `encrypt`: given a message, the recipient's public key, and the sender's private and public signing key pair, encrypt the message using the PRE scheme and sign the encrypted message
- `transform`: given an encrypted or re-encrypted message, the transform key from the last recipient to a new recipient, and the proxy's private and public signing key pair, transform the message so it can be decrypted by the new recipient's private key, then sign the reencrypted message.
- `decrypt`: given an encrypted or re-encrypted message and the recipient's private key, decrypt the message then verify the signatures to confirm that the retrieved plaintext matches the plaintext that was originally encrypted.

## Algorithms

The PRE algorithm implemented here was originally suggested in a short paper titled "A Fully Secure Unidirectional and Multi-user Proxy Re-encryption Scheme" by H. Wang and Z. Cao, published in the proceedings of the ACM Conference on Computer and Communications Security (CCS) in 2009. The algorithm was enhanced in a paper titled "A Multi-User CCA-Secure Proxy Re-Encryption Scheme" by Y. Cai and X. Liu, published in the proceedings of the IEEE 12th International Conference on Dependable, Autonomic, and Secure Computing in 2014.

The algorithms in these papers were very generic and made no implementation choices. They specified only the use of a bilinear pairing function. We made a number of implementation choices. Foremost, we use the optimal Ate pairing as our pairing function. This requires a "pairing-friendly" elliptic curve; we chose a Barreto-Naehrig curve, which supports efficient implementation of the pairing.

Our implementation was guided by the following papers:

- "Pairing-Friendly Elliptic Curves of Prime Order" by P.S.L.M. Barreto and M. Naehrig, published in _Proceedings of the 12th International Workshop on Selected Areas in Cryptography (SAC)_, 2006, pp. 319-331.

- "Constructing Tower Extensions of Finite Fields for Implementation of Pairing-Based Cryptography" by N. Benger and M. Scott, published in _Proceedings of the 3rd International Workshop on Arithmetic of Finite Fields_, 2010, pp. 180-195.

- "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves" by J. Beuchat et al., published in _Proceedings from the 4th International Conference on Pairing-Based Cryptography_, 2010, pp. 21-39.

- "Implementing Cryptographic Pairings over Barreto-Naehrig Curves" by A. J. Devegili et al., published in _Proceedings from the 1st International Conference on Pairing-Based Cryptography_, 2007, pp. 197-207.

- "Multiplication and Squaring on Pairing-Friendly Fields" by A. J. Devegili et al., published in 2006 and available at http://eprint.iacr.org/2006/471.

- "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions" by R. Granger and M. Scott, published in _Proceedings from the 13th International Conferencee on Practice and Theory in Public Key Cryptography (PKC)_, 2010, pp. 209-223.

- "Multiplication of Multidigit Numbers on Automata" by A. Karatsuba and Y. Ofman, in the journal _Soviet Physics Doklady_, vol. 7, Jan. 1963.

- "New Software Speed Records for Cryptographic Pairings" by M. Naehrig, R. Niederhagen, and P. Schwabe, in _Proceedings of the 1st International Conference on Progress in Cryptology and Information Security in Latin America (LATINCRYPT)_, 2010, pp. 109-123.

- "On the Final Exponentiation for Calculating Pairings on Ordinary Elliptic Curves" by M. Scott et al., published in _Proceedings of the 3rd International Converence on Pairing-Based Cryptography (PKC)_, 2009, pp. 78-88.

And by the book:
_Guide to Pairing-Based Cryptography_ by N.E. Mrabet and M. Joye, Chapman and Hall/CRC Cryptography and Network Security Series, 2016.

## Code Audit

The NCC Group has conducted an audit of this library - we have a blog post about the audit [here](https://blog.ironcorelabs.com/ironcore-labs-proxy-re-encryption-library-audit-by-ncc-group-f67abe666838), and their findings are available in a public report [here](https://www.nccgroup.trust/us/our-research/proxy-re-encryption-protocol-ironcore-public-report/?research=Public+Reports). The NCC Group audit found that the chosen pairing and elliptic curve are cryptographically sound and secure, and that the Scala implementation is a faithful and correct embodiment of the target protocol.

# The Project

## Project structure

The project is currently all inside the `core` target. 

```
└── core                                [main project]
    ├── js                              [javascript only]
    │   ├── build                       [NPM build]
    │   │   ├── package.json
    │   │   ├── publish.sh
    │   │   └── recrypt.d.ts
    │   └── src
    │       ├── main
    │       └── test
    ├── jvm                             [jvm only]
    │   └── src
    │       ├── main                    [JVM specific API]
    │       └── test
    └── src                             [shared code]
        └── main
            └── scala/com/ironcorelabs
                └── recrypt             [public API for recrypt]
                    └── internal        [internal concepts/structures]
```

Good places to start exploring are 
* core/js/src - com.ironcorelabs.recrypt.Api (JavaScript API)
* core/src/main/scala - com.ironcorelabs.recrypt.CoreApi (Scala API)

## Building

Recrypt requires openjdk8 and sbt 0.13.x and is known to build under Linux and MacOSX. 

https://github.com/paulp/sbt-extras can be used to get sbt.

After you have `java` and `sbt`, simply go into the recrypt directory and run:

```
$ sbt compile
```

## Running Tests

To run tests just run `sbt test` from the root of the project. This will test everything, but will not run the benchmarks.

## ScalaJS

The `core` project supports ScalaJS. All code at `core/src` is compiled for both JVM and JS. Code in `core/js/src` is JavaScript specific and code in `core/jvm/src` is JVM only.

Since ScalaJS doesn't support Scalatest, all tests only execute on the JVM. 

### ScalaJS specific sbt targets

Executable from the root

* `fastOptJS` - creates a human readable .js file. Faster to create, but larger.
* `fullOptJS` - fully optimized .js file. Much slower to create.

## Benchmarks

### Scala

Running the benchmarks in scala requires `libsodium-dev`. Any recent binary version from a package manager should be fine. 

See https://github.com/jedisct1/libsodium  

This version is known to work on Ubuntu 16.04
```
libsodium-dev/xenial,now 1.0.8-5 amd64 [installed]
  Network communication, cryptography and signaturing library - headers
```

To run the benchmarks, run the following from sbt:

`benchmark/jmh:run -wi 10 -i 15 -f1 -t1 bench.*`


The parameters used here are:

 * `-wi`: the number of times to run during warmup
 * `-i`: the number of times to each benchmark
 * `-f`: the number of processes to use during benchmarking
 * `-t`: the number of threads to use during benchmarking

The above command will use a single thread warming up 10 times on each and running each test 15 times.

### JavaScript

To setup the JS benchmarks, run the following from `sbt`:

`clean`

`fullOptJS`

This will generate the fully optimized JS build. Then go into the `core/js/src/test` directory and create a local symlink to the build file via `ln -s ../../target/scala-2.12/recrypt-core-opt.js recrypt-core-opt.js`. Then startup a local server in that directory (via Python, `python -m SimpleHTTPServer`) and go to `localhost:8000/benchmark.html` to run the benchmarks in your browser.


# License


Recrypt is licensed under the [GNU Affero General Public License](LICENSE).
We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information.


Copyright (c)  2017-present  IronCore Labs, Inc.
All rights reserved.
