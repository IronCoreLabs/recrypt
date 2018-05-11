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

import scodec.bits.ByteVector
import scala.scalajs.js.typedarray._

package object recryptjs {
  //Syntax to convert from Uint8Array to ByteVector
  implicit class UInt8ArraySyntax(val intArray: Uint8Array) extends AnyVal {
    def toByteVector: ByteVector = ByteVector.view(TypedArrayBuffer.wrap(new Int8Array(intArray)))
  }

  //Syntax to convert from ByteVector to Uint8Array
  implicit class ByteVectorSyntax(val byteVector: ByteVector) extends AnyVal {
    def toJSArray: Uint8Array = new Uint8Array(byteVector.toArray.toTypedArray)
  }
}
