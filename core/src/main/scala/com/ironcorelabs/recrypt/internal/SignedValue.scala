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

import cats.syntax.contravariant._

/**
 * Contains a payload, publicKey and signature. This class is also hashable itself,
 * but will not take the signature into account.
 */
final case class SignedValue[A](publicSigningKey: PublicSigningKey, signature: Signature, payload: A)

object SignedValue {
  //Used to create a value which will be signed, later. This should only be done immediately before
  //signing. Tests ensure that the signature isn't part of the "hashable" instance.
  def withEmptySignature[A](publicSigningKey: PublicSigningKey, payload: A): SignedValue[A] =
    SignedValue(publicSigningKey, Signature.empty, payload)
  implicit def hashable[A](implicit hashableA: Hashable[A]): Hashable[SignedValue[A]] =
    Hashable[(PublicSigningKey, A)].contramap {
      case SignedValue(key, _, payload) => (key, payload)
    }
}
