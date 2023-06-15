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
import spire.algebra.Field
import Fp.implicits._
import Fp480.implicits._
import com.ironcorelabs.recrypt.syntax.hashable._

class FP12ElemTest extends com.ironcorelabs.recrypt.TestBase {
  import Arbitraries._
  implicit override val generatorDrivenConfig: PropertyCheckConfiguration = PropertyCheckConfiguration(minSuccessful = 20)
  val fp12Zero = Field[FP12Elem[Fp]].zero
  val fp12One = Field[FP12Elem[Fp]].one

  "square" should {
    "be the same as ^2" in {
      forAll { (one: FP12Elem[Fp]) => one.square shouldBe one ^ 2 }
      forAll { (one: FP12Elem[Fp]) => one.square.square shouldBe one ^ 4 }
      forAll { (one: FP12Elem[Fp]) => one.square.square.square shouldBe one ^ 8 }
    }

    "be the same as times self" in {
      forAll { (one: FP12Elem[Fp]) => one.square shouldBe one * one }
    }
  }

  "hashable" should {
    "always roundtrip with BytesDecoder" in {
      forAll { (one: FP12Elem[Fp]) => FP12Elem.byteDecoderFP12Elem[Fp].decode(one.toHashBytes).value shouldBe one }
      forAll { (one: FP12Elem[Fp480]) => FP12Elem.byteDecoderFP12Elem[Fp480].decode(one.toHashBytes).value shouldBe one }
    }
  }

  "inverse" should {
    "end up in one when times itself" in {
      forAll { (one: FP12Elem[Fp]) =>
        whenever(one != fp12Zero) {
          one.inverse * one shouldBe fp12One
        }
      }
    }
  }

  "x - y" should {
    "be the same as x + y * (-1) " in {
      forAll { (one: FP12Elem[Fp], two: FP12Elem[Fp]) =>
        val expected = (one - two)
        val result = one + (two * (Field[FP2Elem[Fp]].one * (-1)))
        result shouldBe expected
      }
    }
  }

  "x ^ (z + zz)" should {
    "be the same as x ^z * x ^zz for Fp" in {
      forAll { (fp2: FP12Elem[Fp], iRaw: BigInt, jRaw: BigInt) =>
        val (i, j) = (iRaw.abs, jRaw.abs)
        (fp2 ^ i) * (fp2 ^ j) shouldBe fp2 ^ (i + j)
      }
    }
    "be the same as x ^z * x ^zz for Fp480" in {
      forAll { (fp2: FP12Elem[Fp480], iRaw: BigInt, jRaw: BigInt) =>
        val (i, j) = (iRaw.abs, jRaw.abs)
        (fp2 ^ i) * (fp2 ^ j) shouldBe fp2 ^ (i + j)
      }
    }
  }
  "hashable" should {
    "be known value" in {
      val fp6 = FP6Elem.create(Fp(100), Fp(200), Fp(300), Fp(400), Fp(500), Fp(600))
      FP12Elem[Fp](fp6, fp6).toHashBytes shouldBe hex"0x000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000001f40000000000000000000000000000000000000000000000000000000000000258000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000001f40000000000000000000000000000000000000000000000000000000000000258"
    }
  }
  "create" should {
    "create the same element" in {
      val fp6a = FP6Elem.create(Fp(100), Fp(200), Fp(300), Fp(400), Fp(500), Fp(600))
      val fp6b = FP6Elem.create(Fp(700), Fp(800), Fp(900), Fp(1000), Fp(1100), Fp(1200))
      val expected = FP12Elem(fp6a, fp6b)
      val result = FP12Elem.create(Fp(100), Fp(200), Fp(300), Fp(400), Fp(500), Fp(600), Fp(700), Fp(800), Fp(900), Fp(1000), Fp(1100), Fp(1200))
      result shouldBe expected
    }
  }
}
