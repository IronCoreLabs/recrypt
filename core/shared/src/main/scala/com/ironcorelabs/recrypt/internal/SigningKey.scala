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

final case class PublicSigningKey(bytes: ByteVector) extends AnyVal

object PublicSigningKey {
  implicit val hashable: Hashable[PublicSigningKey] = Hashable.by {
    case PublicSigningKey(bytes) => bytes
  }
  val empty: PublicSigningKey = PublicSigningKey(ByteVector.empty)
}

final case class PrivateSigningKey(bytes: ByteVector) extends AnyVal

object PrivateSigningKey {
  val empty: PrivateSigningKey = PrivateSigningKey(ByteVector.empty)
}

final case class Signature(bytes: ByteVector) extends AnyVal

object Signature {
  val empty = Signature(ByteVector.empty)
}

