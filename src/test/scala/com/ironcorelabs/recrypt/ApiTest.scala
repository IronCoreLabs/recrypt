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

package com.ironcorelabs.recrypt

import scodec.bits._
import cats.effect.IO
import spire.implicits._
import spire.algebra.Field
import internal.Fp.implicits._

class ApiTest extends TestBase {
  import ApiTest._
  private val randomIO = {
    //Start with a known value, we'll just add one to it each time
    var i = 100L
    val hashFunc = java.security.MessageDigest.getInstance("SHA-256").digest(_: Array[Byte])
    IO {
      i += 1
      ByteVector.view(hashFunc(List(i.byteValue).toArray))
    }
  }

  val privateSigningKey = PrivateSigningKey.empty
  val publicSigningKey = PublicSigningKey.empty
  //This is very clearly not a "correct" signature, but it does test that the message calculated on verify is correct.
  val api = new Api(randomIO, Ed25519Signing((_, bytes) => Signature(bytes), (_, message, sig) => message == sig.bytes))

  "augmentPrivateKey" should {
    "compute the sum of two PrivateKeys" in {
      val p1 = PrivateKey(ByteVector.view(Array[Byte](4, 8, 15, 16, 23, 42)))
      val p2 = PrivateKey(ByteVector.view(Array[Byte](42, 37, 73, 13, 100, 12)))
      val bvSum = ByteVector.view(Array[Byte](46, 45, 88, 29, 123, 54))
      // augmentPrivateKey will pad the PrivateKeys, so the rhs must be padded as well
      api.augmentPrivateKey(p1, p2) shouldBe PrivateKey(internal.Fp.bigIntToByteVector(internal.Fp(bvSum)))
    }
  }

  "end to end encrypt/decrypt" should {
    "yield expected result using unaugmented keys" in {
      val io = for {
        plaintext <- api.generatePlaintext
        masterKeys <- api.generateKeyPair
        (masterPrivate, masterPublic) = masterKeys
        deviceKeys <- api.generateKeyPair
        (devicePrivate, devicePublic) = deviceKeys
        encryptedMessage <- api.encrypt(plaintext, masterPublic, publicSigningKey, privateSigningKey)
        masterToDeviceTransformKey <- api.generateTransformKey(masterPrivate, devicePublic, publicSigningKey, privateSigningKey)
        transformedMessage <- api.transform(encryptedMessage, masterToDeviceTransformKey, publicSigningKey, privateSigningKey)
      } yield plaintext -> api.decrypt(transformedMessage, devicePrivate)
      val (expectedResult, actualResult) = io.unsafeRunSync()
      actualResult.value shouldBe expectedResult
    }

    "yield expected result using augmented keys" in {
      val io = for {
        plaintext <- api.generatePlaintext
        masterKeys <- api.generateKeyPair
        (masterPrivate, clientGeneratedPublic) = masterKeys
        deviceKeys <- api.generateKeyPair
        (devicePrivate, devicePublic) = deviceKeys
        //These keys would be kept secret by a 2nd party, in this case the "server"
        serverKeys <- api.generateKeyPair
        (serverPrivate, serverPublic) = serverKeys
        //the client sends `clientGeneratedPublic` to the server and the server will augment it. All
        //future data will be encrypted to the augmented public.
        masterPublic <- clientGeneratedPublic.augment(serverPublic).toIO
        encryptedMessage <- api.encrypt(plaintext, masterPublic, publicSigningKey, privateSigningKey)
        //This is the transform key computed by the client.
        masterToDeviceTransformKey <- api.generateTransformKey(masterPrivate, devicePublic, publicSigningKey, privateSigningKey)
        //2nd party will compute this, in our case the server.
        augmentedTransformKey <- masterToDeviceTransformKey.augment(serverPrivate).toIO
        transformedMessage <- api.transform(encryptedMessage, augmentedTransformKey, publicSigningKey, privateSigningKey)
        //Even though we augmented, this should work on the client per normal.
      } yield plaintext -> api.decrypt(transformedMessage, devicePrivate)
      val (expectedResult, actualResult) = io.unsafeRunSync()
      actualResult.value shouldBe expectedResult
    }

    "yield expected result using 2 levels of augmented keys" in {
      val io = for {
        plaintext <- api.generatePlaintext
        masterKeys <- api.generateKeyPair
        (masterGroupPrivate, clientGeneratedGroupPublic) = masterKeys
        userKeys <- api.generateKeyPair
        (masterUserPrivate, clientGeneratedUserPublic) = userKeys
        deviceKeys <- api.generateKeyPair
        (devicePrivate, devicePublic) = deviceKeys
        groupServerKeys <- api.generateKeyPair
        (serverGroupPrivate, serverGroupPublic) = groupServerKeys
        userServerKeys <- api.generateKeyPair
        (serverUserPrivate, serverUserPublic) = userServerKeys
        //Augment the group and user keys (which would be done by the proxy server)
        masterGroupPublic <- clientGeneratedGroupPublic.augment(serverGroupPublic).toIO
        masterUserPublic <- clientGeneratedUserPublic.augment(serverUserPublic).toIO
        groupToUserTransformKey <- api.generateTransformKey(masterGroupPrivate, masterUserPublic, publicSigningKey, privateSigningKey)
        userToDeviceTransformKey <- api.generateTransformKey(masterUserPrivate, devicePublic, publicSigningKey, privateSigningKey)
        augmentedGroupToUserTransform <- groupToUserTransformKey.augment(serverGroupPrivate).toIO
        augmentedUserToDeviceTransform <- userToDeviceTransformKey.augment(serverUserPrivate).toIO
        //Encrypt to the augmented key of the group.
        encryptedMessage <- api.encrypt(plaintext, masterGroupPublic, publicSigningKey, privateSigningKey)
        transformedToUserMessage <- api.transform(encryptedMessage, augmentedGroupToUserTransform, publicSigningKey, privateSigningKey)
        transformedToDeviceMessage <- api.transform(transformedToUserMessage, augmentedUserToDeviceTransform, publicSigningKey, privateSigningKey)
      } yield plaintext -> api.decrypt(transformedToDeviceMessage, devicePrivate)
      val (expectedResult, actualResult) = io.unsafeRunSync()
      actualResult.value shouldBe expectedResult
    }

    "yield expected result using 2 levels" in {
      val io = for {
        plaintext <- api.generatePlaintext
        masterKeys <- api.generateKeyPair
        (masterGroupPrivate, masterGroupPublic) = masterKeys
        userKeys <- api.generateKeyPair
        (masterUserPrivate, masterUserPublic) = userKeys
        deviceKeys <- api.generateKeyPair
        (devicePrivate, devicePublic) = deviceKeys
        groupToUserTransformKey <- api.generateTransformKey(masterGroupPrivate, masterUserPublic, publicSigningKey, privateSigningKey)
        userToDeviceTransformKey <- api.generateTransformKey(masterUserPrivate, devicePublic, publicSigningKey, privateSigningKey)
        //Encrypt to the augmented key of the group.
        encryptedMessage <- api.encrypt(plaintext, masterGroupPublic, publicSigningKey, privateSigningKey)
        transformedToUserMessage <- api.transform(encryptedMessage, groupToUserTransformKey, publicSigningKey, privateSigningKey)
        transformedToDeviceMessage <- api.transform(transformedToUserMessage, userToDeviceTransformKey, publicSigningKey, privateSigningKey)
      } yield plaintext -> api.decrypt(transformedToDeviceMessage, devicePrivate)
      val (expectedResult, actualResult) = io.unsafeRunSync()
      actualResult.value shouldBe expectedResult
    }

    "work with transform to same key" in {
      val io = for {
        plaintext <- api.generatePlaintext
        masterKeys <- api.generateKeyPair
        (masterPrivate, masterPublic) = masterKeys
        encryptedMessage <- api.encrypt(plaintext, masterPublic, publicSigningKey, privateSigningKey)
        masterToMasterTransformKey <- api.generateTransformKey(masterPrivate, masterPublic, publicSigningKey, privateSigningKey)
        transformedMessage <- api.transform(encryptedMessage, masterToMasterTransformKey, publicSigningKey, privateSigningKey)
      } yield plaintext -> api.decrypt(transformedMessage, masterPrivate)
      val (expectedResult, actualResult) = io.unsafeRunSync()
      actualResult.value shouldBe expectedResult
    }
  }

  "deriveSymmetricKey" should {
    val plaintext = Plaintext(hex"0x28c0f558c02d983d7c652f16acbe91a566ac420fe02e41cf6d4f09a107f75cf76b6776ebb53365100ebeb7fa332995ae7bdddf0779fe79e1f43d5c51a73ced0a8cf5789804a79960ccf1a64bd55a923f4786d31ec06bf33e739254016d077b838e739f85586087e52ab659471df3904035e5e1f7ad6ac7b9f9dba6daf39e3f882b583e309c03e35ae7dfd4ed063b6c226bb3338627772e4c9a556fee7f3f96030ae1e265654fc322015a1c2d50eb273cd8b0e1e0353e6b09749343b5fe72ae2f302bebc527aca6ec465a95c4b41efe174eb5165993a30a922434a6f45cbafda201d6540bf2202c65751c90e4cd87e1b690997d9cd23474ef9ace4def3f17cbdd648c8545eaceb3f28c166f720fd8dd87b47523c55a52e32f8c1595a586763276411e8bd4400fac41234277cc560e919f76b21d757cda7c253078927e75482ee2759b222bf4fb070ab3032c9556a069d754efc3c0e63533311b29334108a5121a7e4018782324bf2c1517b6fe4df7a1bbb34c985c6d0796ff1e18ed80fd78d402")
    "produce known value" in {
      //If we're breaking this we better have versioned the api.
      api.deriveSymmetricKey(plaintext) shouldBe DecryptedSymmetricKey(hex"0x0e62a3e388cb0ca3279792353f7fcad75acf180d430a5c69e0a68be96520f454")
    }
  }

  "end to end Schnorr signing" should {
    //We don't support this in general because we lose type safety. For tests we'll just allow it.
    implicit val hashableByteVector = Hashable.by[ByteVector](identity)
    val message = hex"deadbeef"
    "round-trip successfully" in {
      val io = for {
        masterKeys <- api.generateKeyPair
        (masterPrivate, clientPublic) = masterKeys
        serverKeys <- api.generateKeyPair
        (serverPrivate, serverPublic) = serverKeys
        masterPublic <- clientPublic.augment(serverPublic).toIO
        signature <- api.schnorrSign(masterPrivate, masterPublic, message)
      } yield api.schnorrVerify(masterPublic, serverPrivate, message, signature)
      io.unsafeRunSync() shouldBe true
    }
    "fail a bad signature" in {
      val io = for {
        masterKeys <- api.generateKeyPair
        (masterPrivate, clientPublic) = masterKeys
        serverKeys <- api.generateKeyPair
        (serverPrivate, serverPublic) = serverKeys
        masterPublic <- clientPublic.augment(serverPublic).toIO
        signature <- api.schnorrSign(masterPrivate, masterPublic, message)
      } yield api.schnorrVerify(masterPublic, serverPrivate, hex"deadfeeb", signature)
      io.unsafeRunSync() shouldBe false
    }
  }

  "derivePrivateKey" should {
    import syntax.hashable._
    val plaintext = Plaintext(hex"0x28c0f558c02d983d7c652f16acbe91a566ac420fe02e41cf6d4f09a107f75cf76b6776ebb53365100ebeb7fa332995ae7bdddf0779fe79e1f43d5c51a73ced0a8cf5789804a79960ccf1a64bd55a923f4786d31ec06bf33e739254016d077b838e739f85586087e52ab659471df3904035e5e1f7ad6ac7b9f9dba6daf39e3f882b583e309c03e35ae7dfd4ed063b6c226bb3338627772e4c9a556fee7f3f96030ae1e265654fc322015a1c2d50eb273cd8b0e1e0353e6b09749343b5fe72ae2f302bebc527aca6ec465a95c4b41efe174eb5165993a30a922434a6f45cbafda201d6540bf2202c65751c90e4cd87e1b690997d9cd23474ef9ace4def3f17cbdd648c8545eaceb3f28c166f720fd8dd87b47523c55a52e32f8c1595a586763276411e8bd4400fac41234277cc560e919f76b21d757cda7c253078927e75482ee2759b222bf4fb070ab3032c9556a069d754efc3c0e63533311b29334108a5121a7e4018782324bf2c1517b6fe4df7a1bbb34c985c6d0796ff1e18ed80fd78d402")
    "produce known value" in {
      //If we're breaking this we better have versioned the api.
      api.derivePrivateKey(plaintext) shouldBe PrivateKey(internal.Fp(BigInt("6506662011482432737221024072896425758901435651355026438261435484249092322388")).toHashBytes)
    }
  }

  "transformKeyTransform" should {
    val transformKey = TransformKey(
      PublicKey(hex"0x496929ec2914555bfd15c3313f01706505132d92d1cf72f41a7271902c7df443", hex"0x55c873a4de831450c3ea005557ffecdbbd11918a6c66830513860cd767dde192").value,
      PublicKey(hex"0x628f84de59e7dbdd2c3064bb23a7769f5ac4e350dad330a816cbf2251506c6f7", hex"0x660557c7f5a3102a508a7488a6de2f13c635fff239d68e064e9218f0e3980ef2").value,
      EncryptedElement(hex"0x3f0249c3c238ef3f7009d2eddf8737c0ff1020256a42cf4c1f5b728266af924d878fbe6caac0b9fcb5785bb262a69cff0f654a073c118100a5b70795ba5df9c62faeda574cdc5b00f8a750b84ff36ffea80f7a5bf7d408dd9a6f5163043c94c30eda58e30cbf738404455ecd018a4dde91a00b1c7adcca4d66f8c8609cc3ece853b011c91656d8927cca3497caac2dd790a51c9cb381371a4ba60202278a6c156f92764941362bd779f72296f545b7dfe0dcc76109906e141e2b2b927b77a6c96cc1c71d9367775c34711ade6a98650ea7efdcb1376fd70316a98126e5f8a0a814dac11961efe62c09c6bb0e6e10d8a1ff9f022aa81501bdb8c6e6afd2719862376eb2087241260033b5ee00e09da6c5ef99bc67c3b856f73fae7fb1f8b9e59625a4a69b1a36658ec728c4dbc6dd83007550bbe03dbcb9a8a474cb75dde0a4b58e43d5a15d85000cce2dca1232523d6eba70bd006ca690dce649908eaded30ae0f52b6ca0a73183e25947de43d8100200d4e6debb9a6409413753ae1f4faf8f1"),
      HashedValue(hex"0x4a40fc771f0c5625d2ef6783013c52eece1697e71c6f82c3aa58396485c2a6c1713527192c3a7ed9103aca79a39f08a154723602bb768655fdd499f8062b461a5752395183b7743fb6ed688a856ef42aae259df29f52678ef0fccb91adb5374d10820c4e85917c4a1906cb06f537158c0556ecfaa55c874f388823ab9270a536").value,
      publicSigningKey,
      Signature(hex"0xaaaaa")
    )
    "roundtrip" in {
      val internal = CoreApi.transformKeyTransform(transformKey).value
      val result = CoreApi.reencryptionKeyTransform(internal).value
      result shouldBe transformKey
    }
  }

  "hashedValueTransform" should {
    "roundtrip" in {
      val initialValue: HashedValue = HashedValue(hex"0x4a40fc771f0c5625d2ef6783013c52eece1697e71c6f82c3aa58396485c2a6c1713527192c3a7ed9103aca79a39f08a154723602bb768655fdd499f8062b461a5752395183b7743fb6ed688a856ef42aae259df29f52678ef0fccb91adb5374d10820c4e85917c4a1906cb06f537158c0556ecfaa55c874f388823ab9270a536").value
      val internal = CoreApi.hashedValueTransform(initialValue).value
      val result = CoreApi.hashedValueTransform(internal)
      result.value shouldBe initialValue
    }
  }

  "publicKeyTransform" should {
    "roundtrip" in {
      val publicKey = PublicKey(hex"0x496929ec2914555bfd15c3313f01706505132d92d1cf72f41a7271902c7df443", hex"0x55c873a4de831450c3ea005557ffecdbbd11918a6c66830513860cd767dde192").value
      val internal = CoreApi.publicKeyTransform(publicKey)
      val result = CoreApi.publicKeyTransform(internal).value
      result shouldBe publicKey
    }
  }

  "generateGTElem" should {
    "always produce an rth root" in {
      1.to(100).foreach { _ =>
        val gTElem = api.generateGTElem.unsafeRunSync()
        val rthPow = gTElem ^ internal.Fp.Order
        rthPow shouldBe Field[internal.FP12Elem[internal.Fp]].one
      }
    }
  }

  "generatePlaintext" should {
    val fp12One = Field[internal.FP12Elem[internal.Fp]].one
    "always produce an rth root" in {
      1.to(20).foreach { _ =>
        val plaintext = api.generatePlaintext.unsafeRunSync()
        val fp12 = CoreApi.plaintextTransform(plaintext).getOrElse(fp12One)
        val rthPow = fp12 ^ internal.Fp.Order
        rthPow shouldBe fp12One
      }
    }
  }
}

object ApiTest {
  //Hacky syntax to allow us to throw the messages if we want (in the tests).
  implicit class EitherApiErrorSyntax[A](val either: Either[ApiError, A]) {
    def toIO: IO[A] = either.fold(message => IO.raiseError(new Exception(message.toString)), IO.pure)
  }
}
