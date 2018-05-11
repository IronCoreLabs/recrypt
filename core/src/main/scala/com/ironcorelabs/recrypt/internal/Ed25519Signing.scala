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

import scodec.bits.ByteVector

/**
 * An interface which defines how to sign and verify in Recrypt.
 */
abstract class Ed25519Signing {
  /**
   * Sign message using privateSigningKey.
   */
  def sign[A: Hashable](privateKey: PrivateSigningKey, message: A): Signature
  /**
   * Verify that signature is valid for message using PublicSigningKey
   */
  def verify[A: Hashable](publicKey: PublicSigningKey, message: A, signature: Signature): Boolean
}
object Ed25519Signing {
  def apply(
    signF: (PrivateSigningKey, ByteVector) => Signature,
    verifyF: (PublicSigningKey, ByteVector, Signature) => Boolean
  ): Ed25519Signing = new Ed25519Signing {
    def sign[A](privateKey: PrivateSigningKey, message: A)(implicit hashableA: Hashable[A]): Signature =
      signF(privateKey, hashableA(message))
    def verify[A](publicKey: PublicSigningKey, message: A, signature: Signature)(implicit hashableA: Hashable[A]): Boolean =
      verifyF(publicKey, hashableA(message), signature)
  }
}
