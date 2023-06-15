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

import cats.data.NonEmptyVector
import scodec.bits.ByteVector
import com.ironcorelabs.recrypt.syntax.hashable._

/**
 * The AuthHash is a value included in an encrypted message that can be used when the message
 * is decrypted ot ensure that you got the same value out as the one that was originally encrypted.
 * It is a hash of the plaintext.
 */
final case class AuthHash(bytes: ByteVector)

object AuthHash {
  implicit val hashable: Hashable[AuthHash] = Hashable.by[AuthHash](_.bytes)
  def create[A <: BigInt: Hashable](sha256: Sha256Hash, ephemeralPublicKey: PublicKey[A], plaintext: FP12Elem[A]): AuthHash =
    AuthHash(sha256((ephemeralPublicKey, plaintext)))
}

/**
 * ADT for an encrypted value. This represents either an initially encrypted value or one that has
 * been transformed one or more times.
 */
sealed abstract class EncryptedValue[A <: BigInt] {
  def fold[B](f: EncryptedOnceValue[A] => B, g: ReencryptedValue[A] => B): B = this match {
    case e: EncryptedOnceValue[_] => f(e)
    case r: ReencryptedValue[_] => g(r)
  }
  def authHash: AuthHash
  def ephemeralPublicKey: PublicKey[A]
}

object EncryptedValue {
  implicit def hashable[A <: BigInt: Hashable]: Hashable[EncryptedValue[A]] = Hashable.by[EncryptedValue[A]] {
    case EncryptedOnceValue(ephemeralPublicKey, encryptedMessage, authHash) =>
      ephemeralPublicKey.toHashBytes ++ encryptedMessage.toHashBytes ++ authHash.toHashBytes
    case ReencryptedValue(ephemeralPublicKey, encryptedMessage, authHash, blocks) =>
      ephemeralPublicKey.toHashBytes ++ encryptedMessage.toHashBytes ++ authHash.toHashBytes ++ blocks.toHashBytes
  }
}

/**
 * A value which has been encrypted, but not transformed.
 * ephemeralPublicKey - public key of the private key that was used to encrypt
 * encryptedMessage - the encrypted value.
 * authHash - Authentication hash for the plaintext.
 */
final case class EncryptedOnceValue[A <: BigInt](
  ephemeralPublicKey: PublicKey[A],
  encryptedMessage: FP12Elem[A],
  authHash: AuthHash
) extends EncryptedValue[A]

/**
 * A value that has been transformed at least once - this is comprised of the initial encrypted message
 * followed by a set of reencryption blocks, one that is added for each reencryption hop.
 * The number of reencryption hops is equal to the length of the encryptionBlocks Vector.
 *
 * ephemeralPublicKey - public key of the private key that was used to encrypt
 * encryptedMessage - the encrypted value.
 * authHash - Authentication hash for the plaintext.
 * encryptionBlocks - A vector of blocks which describes how to transform the encrypted data to be decrypted by another party.
 */
final case class ReencryptedValue[A <: BigInt](
  ephemeralPublicKey: PublicKey[A],
  encryptedMessage: FP12Elem[A],
  authHash: AuthHash,
  encryptionBlocks: NonEmptyVector[ReencryptionBlock[A]]
) extends EncryptedValue[A]

object ReencryptedValue {
  def fromEncryptedOnce[A <: BigInt](e: EncryptedOnceValue[A], encryptionBlocks: NonEmptyVector[ReencryptionBlock[A]]): ReencryptedValue[A] =
    ReencryptedValue(e.ephemeralPublicKey, e.encryptedMessage, e.authHash, encryptionBlocks)
}

final case class ReencryptionBlock[A <: BigInt](
  publicKey: PublicKey[A],
  encryptedTempKey: FP12Elem[A],
  randomRePublicKey: PublicKey[A],
  randomReEncTempKey: FP12Elem[A]
) {
  def withNewTempKey(encryptedTempKey: FP12Elem[A], randomReEncTempKey: FP12Elem[A]) =
    copy(encryptedTempKey = encryptedTempKey, randomReEncTempKey = randomReEncTempKey)
}

object ReencryptionBlock {
  implicit def hashable[A <: BigInt: Hashable]: Hashable[ReencryptionBlock[A]] = Hashable.by {
    case ReencryptionBlock(publicKey, tempKey, randomRePublicKey, randomReEncTempKey) =>
      publicKey.toHashBytes ++ tempKey.toHashBytes ++ randomRePublicKey.toHashBytes ++ randomReEncTempKey.toHashBytes
  }
}

