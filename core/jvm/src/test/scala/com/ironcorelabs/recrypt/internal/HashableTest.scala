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

import scodec.bits._
import cats.data.NonEmptyVector
import com.ironcorelabs.recrypt.syntax.hashable._

class HashableTest extends com.ironcorelabs.recrypt.TestBase {
  "NonEmptyVector" should {
    "hash in correct order" in {
      NonEmptyVector.of(1.toByte, 2.toByte, 3.toByte).toHashBytes shouldBe hex"010203"
    }
  }
  "Vector" should {
    "hash in correct order" in {
      Vector(1.toByte, 2.toByte, 3.toByte).toHashBytes shouldBe hex"010203"
    }
  }
}
