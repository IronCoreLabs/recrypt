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

import cats.syntax.either._

import scodec.bits.ByteVector

trait BytesDecoder[A] {
  def acceptableSize: Int
  def decode(bytes: ByteVector): Either[ReadError, A]
}

object BytesDecoder {
  def apply[A](implicit decoder: BytesDecoder[A]) = decoder
  def forSize[A](requiredSize: Int)(f: ByteVector => Either[ReadError, A]): BytesDecoder[A] = new BytesDecoder[A] {
    val acceptableSize = requiredSize
    def decode(bytes: ByteVector): Either[ReadError, A] =
      if (bytes.length == requiredSize) f(bytes) else BytesNotCorrectLength(requiredSize, bytes).asLeft
  }
}

sealed abstract class ReadError

case class BytesNotCorrectLength(requiredLength: Int, bytes: ByteVector) extends ReadError
