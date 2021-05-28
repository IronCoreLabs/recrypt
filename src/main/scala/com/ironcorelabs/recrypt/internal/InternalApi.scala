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
import spire.algebra.Field
import point.HomogeneousPoint
import cats.data.NonEmptyVector
import cats.Eq
import cats.implicits._
import spire.implicits._

/**
 * Create a an instance which expects that hashFunc is a cryptographically secure hash function (such as sha256). Note that hash functions which
 * produce more than 256 bits worth will be reduced to values less than `Curve.Order` because they're multiplied by the hash points, which are
 * cyclic in `Curve.Order`.
 */
class InternalApi[FpType <: BigInt: Hashable: Field: ExtensionField: Eq: PairingConfig](
  hashFunc: Sha256Hash,
  ed25519Signing: Ed25519Signing,
  curvePoints: CurvePoints[FpType])(implicit mods: ModsByPrime[FpType]) {
  type ErrorOr[A] = Either[EncryptError, A]

  private[this] val OneByte = 1.toByte
  private[this] val ZeroByte = 0.toByte

  import curvePoints._
  private[internal] val pairing = new Pairing[FpType]()
  val pair = pairing.pair(_, _)

  // Generate one of the rth roots of unity (an element of G_T) given an FP12Elem. This is just a
  // call to the exponentiation routine, but we leave that private and expose this as the
  // public routine.
  def generateRthRoot(fp12Elem: FP12Elem[FpType]): FP12Elem[FpType] = pairing.finalExponentiation(fp12Elem)

  /**
   * Encrypt plaintext to publicKey. This public key encryption is not meant to encrypt arbitrary
   * data; instead, you should generate a random plaintext value (an element of G_T), apply a
   * SHA256 hash to it to generate a 32-bit number, and use that as a key for a symmetric algorithm
   * like AES256-GCM to encrypt the data. Then use this method to encrypt the plaintext.
   *
   * Note that the encrypting privateKey is ephemeral.
   *
   * The result will have the `publicSigningKey` embedded and be signed by the `privateSigningKey`.
   * It also includes a authentication hash that the decrypter can use to confirm that the final
   * result after decryption matches the value that was encrypted.
   * @param publicKey the public key to encrypt to
   * @param plaintext the value to encrypt - must be an element of G_T
   * @param ephemPrivateKey a random private key value chosen just for this plaintext
   * @param publicSigningKey the public portion of the encrypter's signing key pair
   * @param privateSigningKey the private portion of the encrypter's signing key pair
   * @return SignedValue[EncryptedValue] - the plaintext encrypted to the specified public key,
   * along with the authHash, public signing key, and signature
   */
  final def encrypt(
    publicKey: PublicKey[FpType],
    plaintext: FP12Elem[FpType],
    ephemPrivateKey: PrivateKey[FpType],
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): SignedValue[EncryptedValue[FpType]] = {
    val ephemPubKey = publicKeyGen(ephemPrivateKey)
    val encryptedMessage = pair(publicKey.value.times(ephemPrivateKey.toBigInt), g1) * plaintext
    val authHash = AuthHash.create[FpType](hashFunc, ephemPubKey, plaintext)
    signValue[EncryptedValue[FpType]](EncryptedOnceValue(ephemPubKey, encryptedMessage, authHash), publicSigningKey, privateSigningKey)
  }

  /**
   * Decrypt the signedEncryptedValue, verifying that the embedded public signing key matches the signing private key and
   * that the plaintext hash matches the included authHash. This method handles both "encrypted once" and "reencrypted"
   * messages.
   * @param privateKey the private key of the recipient of the message
   * @param signedEncryptedValue the output of encrypt() or reencrypt()
   * @return ErrorOr[FP12Elem] the decrypted value, which is an element of G_T, or an error (which might be
   * caused by an authHash comparision failure or a signature validation failure)
   */
  final def decrypt(privateKey: PrivateKey[FpType], signedEncryptedValue: SignedValue[EncryptedValue[FpType]]): ErrorOr[FP12Elem[FpType]] =
    for {
      goodEncryptedValue <- verifySignedValue(signedEncryptedValue).toRight(SignatureFailed(signedEncryptedValue))
      unverifiedPlaintext = goodEncryptedValue.fold(decryptEncryptedOnce(privateKey, _), decryptReencryptedValue(privateKey, _))
      computedAuthHash = AuthHash.create(hashFunc, goodEncryptedValue.ephemeralPublicKey, unverifiedPlaintext)
      result <- if (goodEncryptedValue.authHash != computedAuthHash) AuthHashMatchFailed(signedEncryptedValue).asLeft
      else unverifiedPlaintext.asRight
    } yield result

  /**
   * Decrypt an `encryptedOnceValue` using privateKey.
   * @param privateKey - The privateKey matching the publicKey that was used in encrypt.
   * @param encryptedValue - The encryptedValue which needs to be decrypted.
   * @return - decrypted value as an FP12 element
   */
  final private[internal] def decryptEncryptedOnce(privateKey: PrivateKey[FpType], encryptedValue: EncryptedOnceValue[FpType]): FP12Elem[FpType] = {
    val EncryptedOnceValue(ephemPubKey, encryptedMessage, _) = encryptedValue
    //This is because
    // m*pair(P,Q)*pair(P,-Q) = m*pair(P,Q)*pair(P,Q)^(-1)  = m
    val maybePlaintext = encryptedMessage * pair(ephemPubKey.value.negate.times(privateKey.toBigInt), g1)
    maybePlaintext
  }

  /**
   * Generate a reencryption key which allows the private key of `toPublicKey` to decrypt a message from `fromPublicKey`.
   * The result will be signed using the signingKey.
   * @param fromPrivateKey - The privateKey matching the fromPublicKey
   * @param toPublicKey - the public key to transform to
   * @param reencryptionPrivateKey - a random private key
   * @param newK - a random FP12 element
   * @param publicSigningKey - Ed25519 public key to include to validate signature
   * @param privateSigningKey - Ed25519 private key to use to sign reencryption key
   * @return reencryption key, along with an Ed25519 public signing key and Ed25519 signature
   */
  final def generateReencryptionKey(
    fromPrivateKey: PrivateKey[FpType],
    toPublicKey: PublicKey[FpType],
    reencryptionPrivateKey: PrivateKey[FpType],
    newK: FP12Elem[FpType],
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): SignedValue[ReencryptionKey[FpType]] = {
    val rePublicKey = publicKeyGen(reencryptionPrivateKey)
    val encryptedK = (pair(toPublicKey.value.times(reencryptionPrivateKey.toBigInt), g1)) * newK
    val hashedK = hash2(newK).add(-g1.times(fromPrivateKey.toBigInt))
    signValue(ReencryptionKey(rePublicKey, toPublicKey, encryptedK, hashedK), publicSigningKey, privateSigningKey)
  }

  /**
   * Reencrypt an EncryptedValue to a new user. This can be the output of either encrypt() or reencrypt().
   * Will fail if the transformKey signature fails to verify.
   * @param signedReencryptionKey - A signed version of the reencryption key,
   *                                which allows a transform from a delegater to a delegatee
   * @param signedEncryptedValue - A signed version of the encrypted value, which is encrypted to the delegating user.
   * @param raRePriKey - A new random private key, which will be used to encrypt the raReK.
   * @param raReK - A new random integer which is used to ensure that the reencryption block cannot be reused.
   * @param privateSigningKey - The ED25519 private key to sign the reencryption block.
   * @param publicSigningKey - The ED25519 public key matching the privateSigningKey.
   * @return - Right(ReencryptedValue) if the value could be successfully reencrypted
   *         - Left(SignatureFailed|ReencryptionKeyIsCorrupt) - if the signatures weren't valid.
   */
  final def reencrypt(
    signedReencryptionKey: SignedValue[ReencryptionKey[FpType]],
    signedEncryptedValue: SignedValue[EncryptedValue[FpType]],
    raRePriKey: PrivateKey[FpType],
    raReK: FP12Elem[FpType],
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): ErrorOr[SignedValue[EncryptedValue[FpType]]] = {
    (
      verifySignedValue(signedEncryptedValue).toRight(SignatureFailed(signedEncryptedValue)),
      verifySignedValue(signedReencryptionKey).toRight(ReencryptionKeyIsCorrupt(signedReencryptionKey))
    ).mapN { (encryptedValue, reencryptionKey) =>
        val reencryptedValue: EncryptedValue[FpType] = encryptedValue.fold[EncryptedValue[FpType]](
          reencryptEncryptedOnce(reencryptionKey, _, raRePriKey, raReK),
          reencryptReencryptedValue(reencryptionKey, _, raRePriKey, raReK)
        )
        signValue(reencryptedValue, publicSigningKey, privateSigningKey)
      }

  }

  /**
   * Verifies the Ed25519 signature on a signed value.
   * @param signedValue an encrypted value with the public signing key and signature
   * @return a Some around the payload if the signature was valid, or None otherwise
   */
  final private[internal] def verifySignedValue[A: Hashable](signedValue: SignedValue[A]): Option[A] =
    if (ed25519Signing.verify(signedValue.publicSigningKey, signedValue, signedValue.signature)) {
      Some(signedValue.payload)
    } else {
      None
    }

  /**
   * Helper function to sign some value of type A (and the publicSigningKey) with privateSigningKey.
   * @param a - the value to sign; must be a type with an associated Hashable instance
   * @param publicSigningKey - the Ed25519 public key to embed in the output; can be used to validate signature
   * @param privateSigningKey - the Ed25519 private key that is used to comptue the signature
   * @return SignedValue[A] - contains the value a, the public signingkey, and the computed signature
   */
  final private[internal] def signValue[A: Hashable](a: A, publicSigningKey: PublicSigningKey, privateSigningKey: PrivateSigningKey): SignedValue[A] = {
    val emptySigned = SignedValue.withEmptySignature(publicSigningKey, a)
    val sig = ed25519Signing.sign(privateSigningKey, emptySigned)
    SignedValue(publicSigningKey, sig, a)
  }

  /**
   * Reencrypt an EncryptedValue to a new user.
   * @param reencryptionKey - The reencryption key, which allows a transform from a delegating user to another user
   * @param encryptedValue - The encrypted value, which is encrypted to the delegating user.
   * @param randomReencryptionPriKey - A new random private key, which will be used to encrypt the randomReencryptionTempKey.
   * @param randomReencryptionTempKey - A new random integer which is used to ensure that the reencryption block cannot be reused.
   * @return - ReencryptedValue as FP12 element
   */
  final private[internal] def reencryptEncryptedOnce(
    reencryptionKey: ReencryptionKey[FpType],
    encryptedValue: EncryptedOnceValue[FpType],
    randomReencryptionPriKey: PrivateKey[FpType],
    randomReencryptionTempKey: FP12Elem[FpType]
  ): ReencryptedValue[FpType] = {
    val ReencryptionKey(rePublicKey, toPublicKey, encryptedSalt, hashedSalt) = reencryptionKey
    val EncryptedOnceValue(ephemPubKeyForEncryptedValue, originalEncryptedMessage, authHash) = encryptedValue
    // Encrypt and produce auth codes for the randomReencryptionTempKey, which we need to ensure
    val randomReencryptionPubKey = publicKeyGen(randomReencryptionPriKey)
    val randomReencryptionEncryptedTempKey = (pair(toPublicKey.value.times(randomReencryptionPriKey.toBigInt), g1)) * randomReencryptionTempKey
    // Because this is the first reencryption, we modify the encryptedMessage using the randomReencryptionTempKey,
    // which can be decrypted using reencryptionKey
    val encryptedMessagePrime = pair(ephemPubKeyForEncryptedValue.value, hashedSalt.add(hash2(randomReencryptionTempKey))) * originalEncryptedMessage
    val newEncryptedData = EncryptedOnceValue(ephemPubKeyForEncryptedValue, encryptedMessagePrime, authHash)
    val reencryptionBlock = ReencryptionBlock(rePublicKey, encryptedSalt, randomReencryptionPubKey, randomReencryptionEncryptedTempKey)
    ReencryptedValue.fromEncryptedOnce(newEncryptedData, NonEmptyVector.of(reencryptionBlock))
  }

  /**
   * Reencrypt a value which was already Reencrypted to yet another person. This is hops 3 through N and can be chained indefinitely.
   * @param reencryptionKey - The key which allows the transform from the current last reencyption block to the reencryptionKey.toPublicKey
   * @param reencryptedValue - Reencrypted value which is going to be transformed
   * @param randomReencryptionPriKey - A new random private key, which will be used to encrypt the randomReencryptionTempKey.
   * @param randomReencryptionTempKey - A new random integer which is used to ensure that the reencryption block cannot be reused.
   */
  final private[internal] def reencryptReencryptedValue(
    reencryptionKey: ReencryptionKey[FpType],
    reencryptedValue: ReencryptedValue[FpType],
    randomReencryptionPriKey: PrivateKey[FpType],
    randomReencryptionTempKey: FP12Elem[FpType]
  ): ReencryptedValue[FpType] = {
    val ReencryptionKey(reencryptionPublicKey, toPublicKey, encryptedTempKey, hashedK) = reencryptionKey
    val reencryptionBlocks = reencryptedValue.encryptionBlocks
    // The algorithm specifies that we should operate on the last element of the reencryptionBlocks
    val reencryptionBlockL = reencryptionBlocks.toVector.last
    // Here anything that is suffixed with `L` means it was a member of the last element
    val ReencryptionBlock(reencryptionPubKeyL, encryptedKL, randomReencryptionPubKeyL, randomReencryptionEncryptedKL) = reencryptionBlockL //scalastyle:ignore

    val encryptedKPrimel = encryptedKL * pair(reencryptionPubKeyL.value, hashedK) // re-encrypted K
    val randomReencryptionPubKey = publicKeyGen(randomReencryptionPriKey)
    val randomReencryptionEncryptedTempKey = pair(toPublicKey.value.times(randomReencryptionPriKey.toBigInt), g1) * randomReencryptionTempKey
    // Modify the random rencryptionEncryptedK with the new randomReencryptionK
    val randomReencryptionKLPrime = randomReencryptionEncryptedKL * pair(randomReencryptionPubKeyL.value, hash2(randomReencryptionTempKey).add(hashedK))
    val reencryptionBlockLPrime = reencryptionBlockL.withNewTempKey(encryptedKPrimel, randomReencryptionKLPrime)
    val newReencryptionBlock = ReencryptionBlock(reencryptionPublicKey, encryptedTempKey, randomReencryptionPubKey, randomReencryptionEncryptedTempKey) //scalastyle:ignore
    // Because we modified the last block, replace it and append the new block as well.
    val newBlocksVector = fromVectorAndNonEmpty(reencryptionBlocks.toVector.init, NonEmptyVector.of(reencryptionBlockLPrime, newReencryptionBlock))
    reencryptedValue.copy(encryptionBlocks = newBlocksVector)
  }

  /**
   * Decrypt a reencryptedValue using the provided privateKey.
   * @param privateKey - The private key that the ReencryptedValue is destined for.
   * @param reencryptedValue - A reencrypted value to decrypt.
   * @return decrypted value as FP12 element
   */
  final private[internal] def decryptReencryptedValue(privateKey: PrivateKey[FpType], reencryptedValue: ReencryptedValue[FpType]): FP12Elem[FpType] =
    reencryptedValue.encryptionBlocks match {
      case encryptionBlocks =>
        //Here anything that is suffixed with `L` means it was a member of the last element
        val reencryptionBlockL = encryptionBlocks.toVector.last
        val ReencryptionBlock(rePubKeyl, encryptedKl, raRePubKeyl, raReEncKl) = reencryptionBlockL
        val secondToLastK = encryptedKl * pair(rePubKeyl.value.negate.times(privateKey.toBigInt), g1)
        val secondToLastRandomReencryptionK = raReEncKl * pair(raRePubKeyl.value.negate.times(privateKey.toBigInt), g1)
        //We're going through the list backwards because we unravel the reencryption blocks from last to first, the last one is special so it's done first.
        val (firstK, firstRandomReencryptionK) = encryptionBlocks.toVector.reverse.tail.foldLeft((secondToLastK, secondToLastRandomReencryptionK)) {
          case ((currentK, currentRandomReencryptionK),
            ReencryptionBlock(nextReencryptionPubKey, nextEncryptedK, nextRandomReencryptionPubKey, nextRandomReencryptionK)) =>
            val currentKHash = hash2(currentK)
            val nextK = nextEncryptedK * pair(nextReencryptionPubKey.value.negate, currentKHash)
            val nextRandomReencyptionK = nextRandomReencryptionK * pair(
              nextRandomReencryptionPubKey.value.negate,
              hash2(currentRandomReencryptionK).add(currentKHash)
            )
            nextK -> nextRandomReencyptionK
        }
        val ReencryptedValue(ephemPubKey, encryptedMessagePrime, _, _) = reencryptedValue
        encryptedMessagePrime * pair(ephemPubKey.value.negate, hash2(firstK).add(hash2(firstRandomReencryptionK)))
    }

  /**
   * Arbitrary hash function to hash an integer into points base field subgroup of the elliptic curve.
   * @param fp12 - An Fp12 element.
   * @return a point in G1, in homogeneous coordinates.
   */
  final def hash2(fp12: FP12Elem[FpType]): HomogeneousPoint[FP2Elem[FpType]] = {
    //Produce a 512 bit byte vector, which ensures we have a big enough value for 480 and Fp
    //We use a constant value combined with the entire fp12 element so we don't leak information about the fp12 structure.
    val bytes = hashFunc((ZeroByte, fp12)) ++ hashFunc((OneByte, fp12))
    hashElement.times(mods.create(bytes)) //Multiplation, which will always occur times the appropriate modded Fp element.
  }
}

