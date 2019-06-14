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

package recryptjs

import scala.scalajs.js
import js.typedarray._

/**
 * All of the datatypes in this file are simply mirrors of their scala counterparts, but with Uint8Arrays instead of the ByteVector that we
 * use internally. They're provided for interop purposes only and none of the apis will work with them directly. This is to increase safety
 * while providing a reasonable API for JS.
 */

class EncryptedValue(
  val ephemeralPublicKey: PublicKey, //Public key which was used to produce the encyptedMessage
  val encryptedMessage: EncryptedMessage, //The encrypted message
  val authHash: AuthHash,
  val transformBlocks: js.Array[TransformBlock], //If empty, decrypt using normal means otherwise it's a reencryption.
  val publicSigningKey: PublicSigningKey,
  val signature: Signature
) extends js.Object

class Keys(val privateKey: PrivateKey, val publicKey: PublicKey) extends js.Object

class PrivateKey(val bytes: Uint8Array) extends js.Object

class PublicKey(val x: Uint8Array, val y: Uint8Array) extends js.Object

class Plaintext(val bytes: Uint8Array) extends js.Object

class DecryptedSymmetricKey(val bytes: Uint8Array) extends js.Object

class EncryptedMessage(val bytes: Uint8Array) extends js.Object

class Signature(val bytes: Uint8Array) extends js.Object

class PublicSigningKey(val bytes: Uint8Array) extends js.Object

class PrivateSigningKey(val bytes: Uint8Array) extends js.Object

class HashedValue(val bytes: Uint8Array) extends js.Object

class EncryptedTempKey(val bytes: Uint8Array) extends js.Object

class AuthHash(val bytes: Uint8Array) extends js.Object

class TransformBlock(
  val publicKey: PublicKey,
  val encryptedTempKey: EncryptedTempKey,
  val randomTransformPublicKey: PublicKey,
  //The encrypted temp key value, which is used to go from the reencrypted value to the encrypted value
  val randomTransformEncryptedTempKey: EncryptedTempKey
) extends js.Object

class TransformKey(
  val ephemeralPublicKey: PublicKey, //The ephemeral public key who encrypted the value
  val toPublicKey: PublicKey, //The person or device that can decrypt the result
  val encryptedTempKey: EncryptedTempKey, //The encrypted K value, which is used to go from the reencrypted value to the encrypted value
  val hashedTempKey: HashedValue,
  val publicSigningKey: PublicSigningKey,
  val signature: Signature
) extends js.Object

class TransformKeyBytes(val bytes: Uint8Array) extends js.Object

class SchnorrMessage(val bytes: Uint8Array) extends js.Object

class SchnorrSignature(val bytes: Uint8Array) extends js.Object
