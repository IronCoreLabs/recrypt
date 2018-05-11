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

import com.ironcorelabs.recrypt.syntax.hashable._
import scodec.bits.ByteVector

/**
 * Newtype for Sha256 hash function.
 */
final case class Sha256Hash(val hash: ByteVector => ByteVector) extends AnyVal {
  def apply[A: Hashable](a: A): ByteVector = hash(a.toHashBytes)
}
