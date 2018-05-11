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

import cats.effect.IO
import scodec.bits.ByteVector
import cats.syntax.either._
import cats.syntax.monad._
import cats.syntax.traverse._
import cats.instances.either._
import cats.instances.list._
import com.ironcorelabs.recrypt.syntax.hashable._
import internal.Fp.implicits._

/**
 * A version of the API that does not have scala specific features in it.
 * @param randomByteVector: An IO that should return a new cryptographically random ByteVector that is at least 32 bytes long on each invocation.
 * @param sha256Impl: An implementation of sha256 for the platform.
 * @param signing: An implementation of Ed25519 for the platform.
 */
class CoreApi(
  randomByteVector: IO[ByteVector],
  sha256Impl: ByteVector => ByteVector,
  signing: Ed25519Signing
) {
  import internal.Fp.implicits._
  private def curvePoints: internal.CurvePoints[internal.Fp] = internal.Fp.curvePoints
  import CoreApi._
  private val sha256 = internal.Sha256Hash(sha256Impl)
  private val encryptInstance = new internal.InternalApi(sha256, signing, curvePoints)
  private val privateKeys = randomByteVector.map(PrivateKey(_))
  private val publicKeyGen = curvePoints.publicKeyGen
  private val schnorrSigning = new internal.SchnorrSigning[internal.Fp](curvePoints.generator, internal.Fp.Order)
  private val randomFp = randomByteVector.map(internal.Fp(_))

  /**
   * Get a new PrivateKey, which is guaranteed to be valid.
   */
  def randomPrivateKey: IO[PrivateKey] = privateKeys

  /**
   * Generate a key pair using the randomByteVector to create private keys.
   */
  def generateKeyPair: IO[(PrivateKey, PublicKey)] =
    privateKeys.map(priv => priv -> publicKeyTransform(publicKeyGen(privateKeyTransform(priv)))
      .getOrElse(throw new Exception("Public key is always defined for valid private key.")))

  /**
   * Compute the public key for the private key, if the privateKey represents an invalid value, raise an error in the IO.
   */
  def computePublicKey(privateKey: PrivateKey): IO[PublicKey] = IO(publicKeyTransform(publicKeyGen(privateKeyTransform(privateKey)))
    //Realistically this should never happen because the private key shouldn't contain a value that goes to the zero point.
    .getOrElse(throw new Exception("privateKey was invalid.")))

  /**
   * Using the randomBytes, generate a random element of G_T, which is one of the rth roots of unit in FP12.
   */
  private[recrypt] def generateGTElem: IO[internal.FP12Elem[internal.Fp]] = {
    val randCoefList = List.fill(12)(randomByteVector.map(bytes => internal.Fp(internal.byteVectorToBigInt(bytes)))).sequence
    randCoefList.map {
      case fp1 :: fp2 :: fp3 :: fp4 :: fp5 :: fp6 :: fp7 :: fp8 :: fp9 :: fp10 :: fp11 :: fp12 :: Nil =>
        encryptInstance.generateRthRoot(internal.FP12Elem.create(fp1, fp2, fp3, fp4, fp5, fp6, fp7, fp8, fp9, fp10, fp11, fp12))
      case _ => throw new Exception("Unless someone breaks the randCoefList above, this can't happen.")
    }
  }

  /**
   * A plaintext is just an element of G_T, converted to a byte vector.
   */
  def generatePlaintext: IO[Plaintext] = generateGTElem.map(fp => Plaintext(fp.toHashBytes))

  /**
   * Transform the value `encryptedValue` using the transformKey. The returned value can be decrypted by the private key
   * associated to the `toPublicKey` in the transformKey.
   *
   * The transformed value will be signed using the privateSigningKey and will embed the publicSigningKey into the returned value.
   */
  def transform(
    encryptedValue: EncryptedValue,
    transformKey: TransformKey,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): IO[EncryptedValue] = for {
    newTempKey <- generateGTElem
    privateKey <- randomPrivateKey
    transformedResult <- reencrypt(newTempKey, privateKey, encryptedValue, transformKey, publicSigningKey, privateSigningKey).toIO
  } yield transformedResult

  /**
   * Encrypt the plaintext to the toPublicKey.
   * @param plaintext - Value to encrypt.
   * @param toPublicKey - Person to encrypt to.
   * @param publicSigningKey - The public signing key of the person (or device) who is encrypting this value
   * @param privateSigningKey - The private signing key of the person (or device) who is encrypting this value
   * @return EncryptedValue which can be decrypted by the matching private key of toPublicKey
   */
  def encrypt(
    plaintext: Plaintext,
    toPublicKey: PublicKey,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): IO[EncryptedValue] = for {
    privateKey <- randomPrivateKey
    encryptedResult <- encrypt(privateKey, toPublicKey, plaintext, publicSigningKey, privateSigningKey).toIO
  } yield encryptedResult

  /**
   * Decrypt the value using privateKey.
   * @param encryptedValue - value we want to decrypt.
   * @param privateKey - PrivateKey which we want to use to decrypt the EncryptedValue.
   * @return An error if the key didn't match or something was corrupted in the EncryptedValue, otherwise the recovered plaintext.
   */
  def decrypt(encryptedValue: EncryptedValue, privateKey: PrivateKey): Either[String, Plaintext] = {
    encryptedValueTransform(encryptedValue)
      .flatMap(e => encryptInstance.decrypt(privateKeyTransform(privateKey), e).leftMap(_.toString))
      .map(fp12 => Plaintext(fp12.toHashBytes))
  }

  def deriveSymmetricKey(p: Plaintext): DecryptedSymmetricKey = DecryptedSymmetricKey(sha256(p))

  /**
   * Derive a private key (which can be used for encrypt) from a plaintext.
   * This is the simplest way to get a private key.
   */
  def derivePrivateKey(p: Plaintext): PrivateKey = PrivateKey(sha256(p))

  /**
   * Generate a transform key which is used to delegate to the `toPublicKey` from the `fromPrivateKey`.
   * @param fromPrivateKey - The person who can currently decrypt the value. (delegator)
   * @param toPublicKey - The person we want to let decrypt the value. This should be the master Public Key if it's going
   *                      to a person, or a device key if it's going to a person's device.(delegatee)
   * @param fromPublicSigningKey - The public signing key of the person (or device) who is generating this transform key
   * @param fromPrivateSigningKey - The private signing key of the person (or device) who is generating this transform key
   * @return The key which will allow the above transformation to take place
   */
  def generateTransformKey(
    fromPrivateKey: PrivateKey,
    toPublicKey: PublicKey,
    fromPublicSigningKey: PublicSigningKey,
    fromPrivateSigningKey: PrivateSigningKey
  ): IO[TransformKey] = for {
    reencryptionPrivateKey <- randomPrivateKey
    tempKey <- generateGTElem
    result <- generateTransformKey(fromPrivateKey, toPublicKey, reencryptionPrivateKey, tempKey, fromPublicSigningKey, fromPrivateSigningKey).toIO
  } yield result

  /**
   * Sign message using privateKey. Also requires the public key, which is included in the
   * hash in order to prevent forgery attacks.
   * @param privateKey - private part of user's master key pair, used to sign message
   * @param publicKey - corresponding (augmented) public key from user's master key pair
   * @param message - actual message to sign
   * @return The signature of the message as a pair of byte vectors r and s, wrapped in an IO. Each part is 32 bytes long.
   */
  def schnorrSign[A: Hashable](
    privateKey: PrivateKey,
    publicKey: PublicKey,
    message: A
  ): IO[SchnorrSignature] = {
    //  Generate random values for K and try to sign until we get one that works
    randomFp
      .map(schnorrSigning.sign(privateKeyTransform(privateKey), publicKey.internalKey, message, _, sha256))
      .iterateUntil(_.isDefined)
      .map { maybeSig =>
        val sig = maybeSig.get //Safe because of above `.isDefined`
        schnorrSignatureTransform(sig)
      }
  }

  /**
   * Verify that the signature of a message is valid, given the public key that corresponds to the private key that
   * signed it. This is complicated by the fact that the public key that was supplied to the sign method was an
   * augmented key, and to validate the signature, we need the pre-augmentation public key that actually matches the
   * private key. But we also need the augmented public key, because we included it in the hash that we used for the
   * signature.
   * @param publicKey - augmented public portion of user's master key pair
   * @param augmentingPrivateKey - server's key that was used to augment user's original master public key
   * @param message - message for which to verify the signature
   * @param signature - signature that was generated for the message using user's master private key
   * @return Boolean - true if signature is valid for the message, given the supplied keys. False otherwise
   */
  def schnorrVerify[A: Hashable](
    publicKey: PublicKey,
    augmentingPrivateKey: PrivateKey,
    message: A,
    signature: SchnorrSignature
  ): Boolean = {
    schnorrSigning.verify(publicKey.internalKey, privateKeyTransform(augmentingPrivateKey), message, schnorrSignatureTransform(signature), sha256)
  }

  private[recrypt] def generateTransformKey(
    fromPrivateKey: PrivateKey,
    toPublicKey: PublicKey,
    reencryptionPrivateKey: PrivateKey,
    tempKey: internal.FP12Elem[internal.Fp],
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ) = {
    reencryptionKeyTransform(
      encryptInstance.generateReencryptionKey(
        privateKeyTransform(fromPrivateKey),
        publicKeyTransform(toPublicKey),
        privateKeyTransform(reencryptionPrivateKey),
        tempKey,
        publicSigningKey,
        privateSigningKey
      )
    )
  }

  private[recrypt] def encrypt(
    ephemeralPrivateKey: PrivateKey,
    toPublicKey: PublicKey,
    plaintext: Plaintext,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ) = for {
    fp12 <- plaintextTransform(plaintext)
    transformedToPublicKey = publicKeyTransform(toPublicKey)
    encryptedValue = encryptInstance.encrypt(transformedToPublicKey, fp12, privateKeyTransform(ephemeralPrivateKey), publicSigningKey, privateSigningKey)
    result <- encryptedValueTransform(encryptedValue)
  } yield result

  private[recrypt] def reencrypt(
    newTempKey: internal.FP12Elem[internal.Fp],
    newPrivateKey: PrivateKey,
    encryptedValue: EncryptedValue,
    transformKey: TransformKey,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ) = for {
    internalTransformKey <- transformKeyTransform(transformKey)
    internalEncryptedValue <- encryptedValueTransform(encryptedValue)
    reencryptResult <- encryptInstance.reencrypt(
      internalTransformKey,
      internalEncryptedValue,
      privateKeyTransform(newPrivateKey),
      newTempKey,
      publicSigningKey,
      privateSigningKey
    ).leftMap(_.toString)
    transformedResult <- encryptedValueTransform(reencryptResult)
  } yield transformedResult

}

object CoreApi {
  import internal.BytesDecoder
  //Transform functions to/from all of types in recrypt's internal types to the Scala exposed types.
  //Note that in most cases there are 2 methods with the same name, this is because the names here often reflect the names in the
  //recrypt core.
  private[recrypt] def publicKeyTransform(p: PublicKey) = p.internalKey
  private[recrypt] def publicKeyTransform(p: internal.PublicKey[internal.Fp]) = PublicKey.fromInternal(p)

  private[recrypt] def privateKeyTransform(p: PrivateKey) = internal.PrivateKey.fromByteVector(p.bytes)

  private[recrypt] def plaintextTransform(d: Plaintext)(implicit bytesDecoder: internal.BytesDecoder[internal.FP12Elem[internal.Fp]]) =
    bytesDecoder.decode(d.bytes).leftMap(_ => "Plaintext could not be transformed.")
  private[recrypt] def plaintextTransform(fp12: internal.FP12Elem[internal.Fp]) = Plaintext(fp12.toHashBytes)

  private[recrypt] def encryptedMessageTransform(fp12: internal.FP12Elem[internal.Fp]): EncryptedMessage = EncryptedMessage(fp12.toHashBytes)

  private[recrypt] def reencryptionBlockTransform(r: internal.ReencryptionBlock[internal.Fp]): Either[String, TransformBlock] = for {
    publicKey <- publicKeyTransform(r.publicKey).toRight("Public key wasn't valid.")
    randomPublicKey <- publicKeyTransform(r.randomRePublicKey).toRight("randomPublicKey wasn't valid.")
    result = TransformBlock(
      publicKey,
      encryptedValueTransform(r.encryptedTempKey),
      randomPublicKey,
      encryptedValueTransform(r.randomReEncTempKey)
    )
  } yield result

  private[recrypt] def transformBlockTransform(r: TransformBlock): Either[String, internal.ReencryptionBlock[internal.Fp]] = {
    val publicKey = publicKeyTransform(r.publicKey)
    val randomPublicKey = publicKeyTransform(r.randomTransformPublicKey)
    for {
      tempKey <- encryptedValueTransform(r.encryptedTempKey).leftMap(_ => "Invalid encryptedTempKey.")
      randomTransformEncryptedTempKey <- encryptedValueTransform(r.randomTransformEncryptedTempKey)
        .leftMap(_ => "Invalid randomTransformEncryptedTempKey")
    } yield internal.ReencryptionBlock(
      publicKey,
      tempKey,
      randomPublicKey,
      randomTransformEncryptedTempKey
    )
  }

  private[recrypt] def transformedValueTransform(t: TransformedValue): Either[String, internal.SignedValue[internal.EncryptedValue[internal.Fp]]] = {
    BytesDecoder[internal.Fp]
    for {
      fp12 <- BytesDecoder[internal.FP12Elem[internal.Fp]].decode(t.encryptedMessage.bytes).leftMap(_ => "Payload of 'encryptedMessage' could not be converted")
      ephemeralPublicKey = publicKeyTransform(t.ephemeralPublicKey)
      authHash = t.authHash
      reencryptionBlocks <- t.transformBlocks.traverse(transformBlockTransform)
    } yield internal.SignedValue(t.publicSigningKey, t.signature, internal.ReencryptedValue(ephemeralPublicKey, fp12, authHash, reencryptionBlocks))
  }

  private[recrypt] def encryptedValueTransform(e: EncryptedValue): Either[String, internal.SignedValue[internal.EncryptedValue[internal.Fp]]] = e match {
    case e: EncryptedOnceValue =>
      for {
        fp12 <- BytesDecoder[internal.FP12Elem[internal.Fp]].decode(e.encryptedMessage.bytes)
          .leftMap(_ => "Payload of 'encryptedMessage' could not be converted")
        ephemeralPublicKey = publicKeyTransform(e.ephemeralPublicKey)
        authHash = e.authHash
      } yield internal.SignedValue(e.publicSigningKey, e.signature, internal.EncryptedOnceValue(ephemeralPublicKey, fp12, authHash))
    case t: TransformedValue => transformedValueTransform(t)

  }
  private[recrypt] def encryptedValueTransform(e: internal.SignedValue[internal.EncryptedValue[internal.Fp]]): Either[String, EncryptedValue] = e.payload.fold(
    { once =>
      val authHash = once.authHash
      publicKeyTransform(once.ephemeralPublicKey)
        .map(key => EncryptedOnceValue(key, EncryptedMessage(once.encryptedMessage.toHashBytes), authHash, e.publicSigningKey, e.signature))
        .toRight("Invalid ephemeralPublicKey")
    },
    { reencrypted =>
      for {
        key <- publicKeyTransform(reencrypted.ephemeralPublicKey).toRight("Invalid ephemeralPublicKey.")
        transformBlocks <- reencrypted.encryptionBlocks.traverse(reencryptionBlockTransform)
      } yield TransformedValue(
        key,
        EncryptedMessage(reencrypted.encryptedMessage.toHashBytes),
        reencrypted.authHash,
        transformBlocks,
        e.publicSigningKey,
        e.signature
      )
    }
  )

  private[recrypt] def encryptedValueTransform(tempKey: internal.FP12Elem[internal.Fp]) = EncryptedElement(tempKey.toHashBytes)
  private[recrypt] def encryptedValueTransform(tempKey: EncryptedElement) = BytesDecoder[internal.FP12Elem[internal.Fp]].decode(tempKey.bytes)
  private[recrypt] def reencryptionKeyTransform(signedKey: internal.SignedValue[internal.ReencryptionKey[internal.Fp]]) = for {
    rePublicKey <- publicKeyTransform(signedKey.payload.rePublicKey).toRight("rePublicKey was the point at infinity.")
    toPublicKey <- publicKeyTransform(signedKey.payload.toPublicKey).toRight("toPublicKey was the point at infinity.")
    encryptedK = encryptedValueTransform(signedKey.payload.encryptedK)
    hashedK <- hashedValueTransform(signedKey.payload.hashedK).leftMap(_.toString)
    publicSigningKey = signedKey.publicSigningKey
    signature = signedKey.signature
  } yield TransformKey(rePublicKey, toPublicKey, encryptedK, hashedK, publicSigningKey, signature)

  private[recrypt] def hashedValueTransform(hashedValue: HashedValue) = internal.point.HomogeneousPoint.fromXYByteVectorOnTwistedCurve(hashedValue.bytes)
  private[recrypt] def hashedValueTransform(hashedValue: internal.point.HomogeneousPoint[internal.FP2Elem[internal.Fp]]) = HashedValue(hashedValue.toHashBytes)

  private[recrypt] def authHashTransform(authHash: HashedValue) = internal.point.HomogeneousPoint.fromXYByteVectorOnTwistedCurve(authHash.bytes)
  private[recrypt] def authHashTransform(authHash: internal.point.HomogeneousPoint[internal.FP2Elem[internal.Fp]]) = HashedValue(authHash.toHashBytes)

  private[recrypt] def transformKeyTransform(k: TransformKey) = for {
    encryptedK <- encryptedValueTransform(k.encryptedTempKey).leftMap(_ => "encryptedTempKey was invalid.")
    rePublicKey = publicKeyTransform(k.ephemeralPublicKey)
    toPublicKey = publicKeyTransform(k.toPublicKey)
    hashedK <- hashedValueTransform(k.hashedTempKey).leftMap(_.toString)
    publicSigningKey = k.publicSigningKey
    signature = k.signature
    result = internal.SignedValue(publicSigningKey, signature, internal.ReencryptionKey(rePublicKey, toPublicKey, encryptedK, hashedK))
  } yield result

  private[recrypt] def schnorrSignatureTransform(signature: SchnorrSignature) = {
    val bigInts = signature.toBigInts
    internal.SchnorrSignature(bigInts._1, bigInts._2)
  }

  private[recrypt] def schnorrSignatureTransform(signature: internal.SchnorrSignature) =
    SchnorrSignature.fromBigInts(signature.r, signature.s)
}
