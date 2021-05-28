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
import org.scalacheck.Arbitrary
import spire.implicits._
import scodec.bits.BitVector

class FpTest extends com.ironcorelabs.recrypt.TestBase {
  import Arbitraries._
  //Things in here are fundemental operations so tehy should work even for 0
  implicit val fpArb = Arbitrary(fpGen)

  "Fp.apply" should {
    "yield expected result" in {
      val result = Fp.Impl(BitVector.bits(List.fill(256)(true)).toByteVector)
      val expectedResult = Fp.Impl(BigInt("50791539541669591690774546266328002110444626558017560467580438981048945568152"))
      result shouldBe expectedResult
    }
  }

  "Fp.negate" should {
    "Always be in Fp" in {
      forAll { (fp: Fp) =>
        val negateResult = spire.algebra.Field[Fp].negate(fp)
        negateResult shouldBe Fp(negateResult)
      }
    }
  }

  "Fp.fastModPrime" should {
    "work for elements greater than 2 * Prime" in {
      forAll { (fp: Fp) =>
        val bigIntFp: BigInt = fp //100% sure that it will be widened to the big int before +
        val biggerThanPrime = bigIntFp + Fp.Prime * 5
        val fastModResult = Fp.fastModPrime(biggerThanPrime)
        fastModResult shouldBe fp
        fastModResult shouldBe positiveMod(biggerThanPrime, Fp.Prime)
      }
    }
    "work for all numbers" in {
      forAll { (b: BigInt) =>
        Fp.fastModPrime(b) shouldBe Fp(b)
      }
    }
  }

  "Fp.reciprocal" should {
    "Always be 1 in *" in {
      forAll { (fp: Fp) =>
        if (fp != Fp.Zero) {
          Fp(fp.reciprocal * fp) shouldBe Fp.One
        } else {
          fp.reciprocal shouldBe Fp.Zero
        }
      }
    }
  }

  "Fp.ModsByPrime.create" should {
    import scodec.bits.ByteVector
    val mods = implicitly[ModsByPrime[Fp]]
    "Create known value for 64 byte array" in {
      val thirty_two_bytes = ByteVector.fill(32)(1.toByte)
      val input = thirty_two_bytes ++ thirty_two_bytes
      mods.create(input) shouldBe Fp(BigInt("52985480557495246266538294759444418497567570469767957953504536616255684048226"))
    }

    "Create known value for another 64 byte array" in {
      val one_bytes = ByteVector.fill(16)(1.toByte)
      val zero_bytes = ByteVector.fill(16)(0.toByte)
      val input = zero_bytes ++ one_bytes ++ zero_bytes ++ one_bytes
      mods.create(input) shouldBe Fp(BigInt("54528517336565915139246673167415770626278933459643464115007152164576808341406"))
    }
  }

}
