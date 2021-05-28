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
/**
 * Classes of errors that happen on Encrypt/Decrypt.
 */
sealed abstract class EncryptError

/**
 * The value couldn't be decrypted because the authentication hash for the encrypted value couldn't be verified.
 */
final case class AuthHashMatchFailed[A <: BigInt](encryptedValue: SignedValue[EncryptedValue[A]]) extends EncryptError

/**
 * The signature for the ReencryptionKey could not be verified.
 */
final case class ReencryptionKeyIsCorrupt[A <: BigInt](key: SignedValue[ReencryptionKey[A]]) extends EncryptError

/**
 * The signature for EncryptedValue could not be verfied.
 */
final case class SignatureFailed[A <: BigInt](reencryptedValue: SignedValue[EncryptedValue[A]]) extends EncryptError

final case class InvalidPoint(pointError: PointError) extends EncryptError
