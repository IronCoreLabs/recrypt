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

import cats.data.NonEmptyVector
import scodec.bits.ByteVector

/**
 * ADT defining a value which is Encrypted. If it's only been encrypted once, it'll be an EncryptedOnceValue, if it's been
 * transformed (delegated) to another person then it'll be a TransformedValue.
 */
sealed abstract class EncryptedValue {
  def ephemeralPublicKey: PublicKey //Public key corresponding to secret key that was used to encrypt the symmetricKey
  def encryptedMessage: EncryptedMessage //The encrypted plaintext
  def authHash: AuthHash
  def publicSigningKey: PublicSigningKey
  def signature: Signature
}

final case class TransformedValue(
  ephemeralPublicKey: PublicKey, //Public key which was used to produce the encryptedMessage
  encryptedMessage: EncryptedMessage, //The encrypted plaintext
  authHash: AuthHash,
  transformBlocks: NonEmptyVector[TransformBlock],
  publicSigningKey: PublicSigningKey,
  signature: Signature
) extends EncryptedValue

final case class EncryptedOnceValue(
  ephemeralPublicKey: PublicKey, //Public key which was used to produce the encryptedMessage
  encryptedMessage: EncryptedMessage, //The encrypted plaintext
  authHash: AuthHash,
  publicSigningKey: PublicSigningKey,
  signature: Signature
) extends EncryptedValue

final case class TransformBlock(
  publicKey: PublicKey, // Public key corresponding to private key used to encrypt the temp key
  encryptedTempKey: EncryptedElement,
  randomTransformPublicKey: PublicKey, // The public key corresponding to the private key used to encrypt the random re-encryption element
  //The encrypted temp key value, which is used to go from the reencrypted value to the encrypted value
  randomTransformEncryptedTempKey: EncryptedElement
)

/**
 * Should be 384 bytes, an FP12Elem.
 */
final case class EncryptedElement(bytes: ByteVector)

object EncryptedElement {
  implicit val hashable: Hashable[EncryptedElement] = Hashable.by(_.bytes)
}
