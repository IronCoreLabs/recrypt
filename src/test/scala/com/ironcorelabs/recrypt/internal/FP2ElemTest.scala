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
import Fp.implicits._
import Fp480.implicits._
import spire.algebra.Field
import com.ironcorelabs.recrypt.syntax.hashable._

class FP2ElemTest extends com.ironcorelabs.recrypt.TestBase {
  import Arbitraries._
  implicit val fp480Arb = org.scalacheck.Arbitrary(nonZeroFp480Gen)

  val fp2Zero = Field[FP2Elem[Fp]].zero
  val fp2One = Field[FP2Elem[Fp]].one
  "square" should {
    "be the same as ^2" in {
      forAll { (one: FP2Elem[Fp]) => one.square shouldBe one ^ 2 }
      forAll { (one: FP2Elem[Fp480]) => one.square shouldBe one ^ 2 }
      forAll { (one: FP2Elem[Fp]) => one.square.square shouldBe one ^ 4 }
      forAll { (one: FP2Elem[Fp]) => one.square.square.square shouldBe one ^ 8 }
      forAll { (one: FP2Elem[Fp480]) => one.square.square.square shouldBe one ^ 8 }
    }

    "be the same as times self" in {
      forAll { (one: FP2Elem[Fp]) => one.square shouldBe one * one }
      forAll { (one: FP2Elem[Fp480]) => one.square shouldBe one * one }
    }
  }

  "toByteVector" should {
    "always roundtrip with fromByteVector" in {
      forAll { (one: FP2Elem[Fp]) => FP2Elem.byteDecoderFP2Elem[Fp].decode(one.toHashBytes).value shouldBe one }
      forAll { (one: FP12Elem[Fp480]) => FP12Elem.byteDecoderFP12Elem[Fp480].decode(one.toHashBytes).value shouldBe one }
    }
  }

  "inverse" should {
    "end up in one when times itself" in {
      forAll { (one: FP2Elem[Fp]) =>
        whenever(one != fp2Zero) {
          one.inverse * one shouldBe fp2One
        }
      }
    }
  }

  "x - y" should {
    "be the same as x + y * (-1) " in {
      forAll { (one: FP2Elem[Fp], two: FP2Elem[Fp]) =>
        val expected = one - two
        val result = one + (two * (-1))
        result shouldBe expected
      }
    }
  }

  "x ^ (z + zz)" should {
    "be the same as x ^z * x ^zz" in {
      forAll { (fp2: FP2Elem[Fp], iRaw: BigInt, jRaw: BigInt) =>
        val (i, j) = (iRaw.abs, jRaw.abs)
        (fp2 ^ i) * (fp2 ^ j) shouldBe fp2 ^ (i + j)
      }
    }
  }
}
