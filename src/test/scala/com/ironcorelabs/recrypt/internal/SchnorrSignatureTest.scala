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
  implicit val hashableByteVector: Hashable[ByteVector] = Hashable.by[ByteVector](identity)
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
    val schnorrSigning = new SchnorrSigning(Fp.curvePoints.generator, Fp.Order, Fp.ExpectedOrderLength)
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

    "verify known good with augmentation" in {
      val augmenting = PrivateKey(Fp(hex"0x85d403b4e6f4b1e19b9572fcbc4751508bffc5ca209fc0bcf3149d54c721be20"))
      val message = hex"0x3135353138313631333539353469e4601ac60b63e2aabd957c2dd293da29420e7e9a315b896c7a00144dc63a2543faa774934f040a33443ddb8cfce3324879e092181ce74e2c759b2dabaac15c2e2b3fb51761429f4ae0b4643dec667acd96787083384077d60c22b65ae9644e479b552c1da72741b83aa454f87bb1df7d81b1109cfb09d943e52cc10a6ec770606158ee851c4e660014637077733523d04d041a780692dabcdf0c0ce170e8a54cf6d1131319609c932992b9441bf5bfcca73d54cfa06406715d1fe76023be1b6cc13270b35d16c013d84a7fc7101e9abb768953b40ddfcb3a4dcd7986502c465021f6284861dbf3fe62ae80c2df0d0b896f976d0ab793588d344e343f41440e446758d9743cbabaf787ea243c312209d238ba89bbe707f7d60ffa253d0e65176a57b3e47769e90feb4f6ceb90a89d7ce71991aae7449d2f8aa3c90f4a25abfa5145f910a82c7852532b7fae9799bdf9b5ef24428c224e468f6d4d10a53c7e454d1521d2d31ee1e479ece79deec2f292b42b70ca37ce4e5b0d88811813b39e617476b56409881635e09dc8c7d5994188a2ba46b5f5540616cb0c9f2b556e5a1150061c2e1733cdc10306d366b70187d9d70e86c22cd3f87e6c98befa460b15d4529d0dace7273da7bdc1413e398f3d70e419e6ebbb8f9cc6545a31334f1a9b937753174c7856cd0460ed3c0361c3d8851784d5298df7ced7e28e470251db113c7151185fdfd0c43455fb7efb5ff321619070eaa0d2450504a8d240eabdc0de7f0bef8d2e99e7a0306505a9a84170fc5b441bdd276384fd2b082901ab251d072343c0d7d34a41b9ff5d50c90610f4c002c24f84c48ef0f11b709f1082a3b8562537a821727fa4b71fff3bde107e93533e33b96638fde110fa93497d4ba4274f006f1e2204e7de41aff8c7c80e26bb7100f5010a3995a3a84827768b344225044565794a68624763694f694a46557a49314e694973496e523563434936496b705856434a392e65794a77615751694f6a51774f53776963326c6b496a6f696247396a595777746332566e6257567564434973496d74705a4349364e5449314c434a70595851694f6a45314e5445344d5459784d7a5573496d5634634349364d5455314d5467784e6a49314e53776963335669496a6f6959574a6a4d54497a496e302e36565331706f6e48725a493245474a6d47366748574f793258456970626335615a355751306f5a583779776f4835755a595a6c7378663448797152656947494671653536694e396438375978665159737772616c73773e00fc622bb17a1cffc0f101e894da65ace242684e402d03242509a60900869d87ff251f613b28457bba230f351fa5b4bb465c94dd67338dcfcfbe893fb52125"
      val publicKey = PublicKey.fromByteVectors(hex"0x3e00fc622bb17a1cffc0f101e894da65ace242684e402d03242509a60900869d", hex"0x87ff251f613b28457bba230f351fa5b4bb465c94dd67338dcfcfbe893fb52125").value
      val (r, s) = com.ironcorelabs.recrypt.SchnorrSignature.unsafeFromBytes(hex"0x8151a7bd378dbb25f4aff9c52d44b8c8576dfffe79901e340f5c8999ab41a18c2cdadd8707882adc17ad605d5ec6809241f4b062909e0ac68cf3e9ae7b9f7854").toBigInts
      schnorrSigning.verify(publicKey, augmenting, message, SchnorrSignature(r, s), sha256) shouldBe true
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
    val schnorrSigning = new SchnorrSigning(Fp480.curvePoints.generator, Fp480.Order, Fp480.ExpectedOrderLength)
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
