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

import scodec.bits.ByteVector
import java.security.MessageDigest

object Sha256 extends (ByteVector => ByteVector) {
  //Since message digests are not thread safe, this should never be used directly.
  //Instead use getSha256Copy.
  private[this] val emptySha256 = MessageDigest.getInstance("SHA-256")
  private def getSha256Copy: MessageDigest = emptySha256.clone().asInstanceOf[MessageDigest]
  def apply(bytes: ByteVector): ByteVector = ByteVector.view(getSha256Copy.digest(bytes.toArray))
}
