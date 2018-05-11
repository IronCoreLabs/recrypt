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

package com.ironcorelabs

import cats.effect.IO

package object recrypt {
  //Re export some of the types
  type PrivateSigningKey = internal.PrivateSigningKey
  val PrivateSigningKey = internal.PrivateSigningKey

  type PublicSigningKey = internal.PublicSigningKey
  val PublicSigningKey = internal.PublicSigningKey

  type Signature = internal.Signature
  val Signature = internal.Signature

  type Hashable[A] = internal.Hashable[A]
  val Hashable = internal.Hashable

  type AuthHash = internal.AuthHash
  val AuthHash = internal.AuthHash

  type Ed25519Signing = internal.Ed25519Signing
  val Ed25519Signing = internal.Ed25519Signing

  implicit class EitherSyntax[A](val either: Either[String, A]) {
    def toIO: IO[A] = either.fold(message => IO.raiseError(new Exception(message)), IO.pure)
  }
}
