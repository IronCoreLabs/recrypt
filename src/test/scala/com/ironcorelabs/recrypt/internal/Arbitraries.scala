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

import point.HomogeneousPoint
import org.scalacheck.{ Arbitrary, Gen }
import spire.algebra.Field

object Arbitraries {
  ///This is the scalacheck generator, but with no 0s.
  val nonZeroBigInt: Gen[BigInt] = {
    val long: Gen[Long] =
      Gen.choose(Long.MinValue, Long.MaxValue).map(x => if (x == 0) 1L else x)

    val gen1: Gen[BigInt] = for { x <- long } yield BigInt(x)
    val gen2: Gen[BigInt] = for { x <- gen1; y <- long } yield x * y
    val gen3: Gen[BigInt] = for { x <- gen2; y <- long } yield x * y
    val gen4: Gen[BigInt] = for { x <- gen3; y <- long } yield x * y

    val gen0: Gen[BigInt] =
      Gen.oneOf(
        BigInt(1),
        BigInt(-1),
        BigInt(Int.MaxValue) + 1,
        BigInt(Int.MinValue) - 1,
        BigInt(Long.MaxValue),
        BigInt(Long.MinValue),
        BigInt(Long.MaxValue) + 1,
        BigInt(Long.MinValue) - 1)

    Gen.frequency((5, gen0), (5, gen1), (4, gen2), (3, gen3), (2, gen4))
  }

  val fpGen = Arbitrary.arbitrary[BigInt].map(Fp(_))
  val fp480Gen = Arbitrary.arbitrary[BigInt].map(Fp480(_))
  implicit val nonZeroFpGen: Gen[Fp.Impl.T] = nonZeroBigInt.map(Fp(_))
  implicit val nonZeroFp480Gen: Gen[Fp480.Impl.T] = nonZeroBigInt.map(Fp480(_))
  implicit def fp2Gen[A <: BigInt: ModsByPrime](implicit genA: Gen[A]): Gen[FP2Elem[A]] = for {
    a <- genA
    b <- genA
  } yield FP2Elem(a, b)
  implicit def fp2Arb[A <: BigInt: ModsByPrime: Gen]: Arbitrary[FP2Elem[A]] = Arbitrary(fp2Gen[A])

  implicit def fp6Gen[A <: BigInt: ModsByPrime](implicit genFp2A: Gen[FP2Elem[A]]): Gen[FP6Elem[A]] = for {
    one <- genFp2A
    two <- genFp2A
    three <- genFp2A
  } yield FP6Elem(one, two, three)

  implicit def fp12Arb[A <: BigInt: Field: ModsByPrime: ExtensionField](implicit genFp6A: Gen[FP6Elem[A]]): Arbitrary[FP12Elem[A]] = Arbitrary(for {
    one <- genFp6A
    two <- genFp6A
  } yield FP12Elem(one, two))

  //Legal Points are ones that satisfy the equation y^2 = x^3 + 3.
  //Generate them by just multiplying the generator point.
  implicit val homogeneousPointArbFp: Arbitrary[HomogeneousPoint[Fp]] = Arbitrary[HomogeneousPoint[Fp]](nonZeroFpGen.map(Fp.curvePoints.generator.times(_)))
  implicit val homogeneousPointArbFp480: Arbitrary[HomogeneousPoint[Fp480]] = Arbitrary[HomogeneousPoint[Fp480]](nonZeroFp480Gen.map(Fp480.curvePoints.generator.times(_)))

  implicit val homogeneousPointArb: Arbitrary[HomogeneousPoint[FP2Elem[Fp]]] = Arbitrary[HomogeneousPoint[FP2Elem[Fp]]](fpGen.map(Fp.curvePoints.g1.times(_)))
  implicit val homogeneousPointArbFP2Elem480: Arbitrary[HomogeneousPoint[FP2Elem[Fp480]]] = Arbitrary[HomogeneousPoint[FP2Elem[Fp480]]](fp480Gen.map(Fp480.curvePoints.g1.times(_)))

  implicit val arbPrivateKey: Arbitrary[PrivateKey[Fp]] = Arbitrary[PrivateKey[Fp]](nonZeroFpGen.map(PrivateKey(_)))

  implicit val arbPublicKey: Arbitrary[PublicKey[Fp]] = Arbitrary(Arbitrary.arbitrary[HomogeneousPoint[Fp]].map(PublicKey(_)))

  implicit val arbPrivateKey480: Arbitrary[PrivateKey[Fp480]] = Arbitrary[PrivateKey[Fp480]](nonZeroFp480Gen.map(PrivateKey(_)))

  implicit val arbPublicKey480: Arbitrary[PublicKey[Fp480]] = Arbitrary(Arbitrary.arbitrary[HomogeneousPoint[Fp480]].map(PublicKey(_)))
}
