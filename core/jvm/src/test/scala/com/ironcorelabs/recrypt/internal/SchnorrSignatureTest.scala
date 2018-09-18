/*
 * Copyright (C) 2017-present  IronCore Labs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.ironcorelabs.recrypt.internal

import scodec.bits._

class SchnorrSignatureTest extends com.ironcorelabs.recrypt.TestBase {

  //We don't support this in general because we lose type safety. For tests we'll just allow it.
  implicit val hashableByteVector = Hashable.by[ByteVector](identity)
  "SchnorrSignature for Fp" should {
    import Fp.implicits._
    val keyGen = new PublicKeyGen(Fp.curvePoints.generator)
    val message = hex"deadbeef"
    val privateKey = PrivateKey(Fp(23))
    val clientKey = keyGen(privateKey)
    val augmentingPrivateKey = PrivateKey(Fp(9999))
    val augmentingPublicKey = keyGen(augmentingPrivateKey)
    val publicKey = clientKey.augment(augmentingPublicKey)
    val testK = BigInt("8675309")
    val expectedSig = new SchnorrSignature(
      BigInt("9430846965827942577422586051201862403907106328723637911544951861530577787464"),
      BigInt("3440285153676249583947010542837795284433926700888774963519491303618013239545")
    )
    val schnorrSigning = new SchnorrSigning(Fp.curvePoints.generator, Fp.Order)
    val sha256 = Sha256Hash(com.ironcorelabs.recrypt.Sha256)
    def sign[A: Hashable](a: A, k: BigInt) = schnorrSigning.sign(privateKey, publicKey, a, k, sha256)
    def verify[A: Hashable](a: A, signature: SchnorrSignature) = schnorrSigning.verify(publicKey, augmentingPrivateKey, a, signature, sha256)
    "fail to sign if passed 0 for k" in {
      sign(message, 0) shouldBe None
    }
    "fail to sign if passed Curve.Order for k" in {
      sign(message, Fp.Order) shouldBe None
    }
    "fail to sign if passed a number greater than Curve.Order for k" in {
      sign(message, Fp.Order + 1) shouldBe None
      sign(message, Fp.Prime - 1) shouldBe None
    }
    "return expected signature" in {
      //  Independently computed signature for this message and keys using Sage
      val sig = sign(message, testK).value
      sig shouldBe expectedSig
    }
    "validate good signature" in {
      verify(message, expectedSig) shouldBe true
    }
    "reject bad signature" in {
      verify(hex"beefdead", expectedSig) shouldBe false
    }
    "round-trip signing/verification" in {
      val sig = sign(
        message,
        BigInt("232323232323232323232323232323232323232323232323232323232323232323")
      ).value
      verify(message, sig) shouldBe true
    }
  }

  "SchnorrSigning on Fp480" should {
    import Fp480.implicits._
    val keyGen = new PublicKeyGen(Fp480.curvePoints.generator)
    val message = hex"deadbeef"
    val privateKey = PrivateKey(Fp480(238792318348L))
    val clientKey = keyGen(privateKey)
    val augmentingPrivateKey = PrivateKey(Fp480(99993223498L))
    val augmentingPublicKey = keyGen(augmentingPrivateKey)
    val publicKey = clientKey.augment(augmentingPublicKey)
    val schnorrSigning = new SchnorrSigning(Fp480.curvePoints.generator, Fp480.Order)
    val sha256 = Sha256Hash(com.ironcorelabs.recrypt.Sha256)
    def sign[A: Hashable](a: A, k: BigInt) = schnorrSigning.sign(privateKey, publicKey, a, k, sha256)
    def verify[A: Hashable](a: A, signature: SchnorrSignature) = schnorrSigning.verify(publicKey, augmentingPrivateKey, a, signature, sha256)

    "succeed for k that is Fp.Order" in {
      verify(message, sign(message, Fp.Order).value) shouldBe true
    }
    "fail with Fp480.Order" in {
      sign(message, Fp480.Order) shouldBe None
    }
    "fail with Fp480.Order + 1" in {
      sign(message, Fp480.Order + 1) shouldBe None
    }
    "fail with Fp480.Prime - 1" in {
      sign(message, Fp480.Prime - 1) shouldBe None
    }
  }
}
