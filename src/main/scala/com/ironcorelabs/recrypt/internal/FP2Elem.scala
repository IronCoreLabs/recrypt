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

import spire.algebra.Field
import cats.kernel.Eq
import cats.implicits._
/**
 * This is the degree 2 extension of the base field FP. It is formed by attaching the variable to
 * Fp, subject to the constraint u^2 + 1 = 0. That is, FP2 = Fp[u]/(u^2 + 1)
 *
 * A value in FP2 is represented as a polynomial a + b * u, where a and b are both elements of Fp.
 */
final case class FP2Elem[A <: BigInt](elem1: A, elem2: A)(implicit mods: ModsByPrime[A]) {
  private def modAndNew(e1: BigInt, e2: BigInt): FP2Elem[A] = FP2Elem(mods.create(e1), mods.create(e2))
  def +(other: FP2Elem[A]): FP2Elem[A] = modAndNew(elem1 + other.elem1, elem2 + other.elem2)

  def -(other: FP2Elem[A]): FP2Elem[A] = modAndNew(elem1 - other.elem1, elem2 - other.elem2)

  def *(other: FP2Elem[A]): FP2Elem[A] = {
    val z0 = elem2 * other.elem2
    val z2 = elem1 * other.elem1
    val z1 = (elem1 + elem2) * (other.elem1 + other.elem2)
    modAndNew(z1 - z2 - z0, z0 - z2)
  }

  def *(scalar: Int): FP2Elem[A] = modAndNew(elem1 * scalar, elem2 * scalar)

  def unary_- : FP2Elem[A] = modAndNew(-elem1, -elem2) //scalastyle:ignore method.name

  def square: FP2Elem[A] = {
    val a2 = elem1 * elem2
    val a3 = a2 + a2
    val b2 = elem2 + elem1
    val b3 = elem2 - elem1
    val b4 = b2 * b3
    modAndNew(a3, b4)
  }

  def inverse: FP2Elem[A] = {
    val mag = elem1.pow(2) + elem2.pow(2)
    val inv = com.ironcorelabs.recrypt.internal.inverse(mag, mods.prime).getOrElse(BigInt(0))
    FP2Elem(mods.create(-elem1 * inv), mods.create(elem2 * inv))
  }

  //This is the element to the p power.
  //Some of the reasoning is as follows
  // x ^ p -x = 0 == x^p = x
  //By the binomial expansion we get:
  // (x + (y * u)) ^ p == x^p + p * (middle terms) + (u^p * y^p)
  // u ^p == -u  which is because our p is congruent to 3 mod 4
  // x^p + -uy^p == x + -uy
  def frobenius: FP2Elem[A] = modAndNew(-elem1, elem2)

  def ^(power: BigInt): FP2Elem[A] = { //scalastyle:ignore
    val bits = scodec.bits.BitVector(power.toByteArray).toIndexedSeq.dropWhile(!_)
    val result = bits.toIndexedSeq.foldLeft(modAndNew(0, 1)) {
      case (cur, bit) =>
        val squareResult = cur * cur
        if (bit) squareResult * this else squareResult
    }
    if (power < 0) result.inverse else result
  }

  override def toString: String = s"$elem1 * u + $elem2"

}

object FP2Elem { //scalastyle:ignore

  def fromBigInts[A <: BigInt](elem1: BigInt, elem2: BigInt)(implicit mods: ModsByPrime[A]): FP2Elem[A] = FP2Elem(mods.create(elem1), mods.create(elem2))
  implicit final def fieldInstance[A <: BigInt](implicit fieldA: Field[A], modsByPrime: ModsByPrime[A]): Field[FP2Elem[A]] =
    new Field[FP2Elem[A]] {

      def negate(x: FP2Elem[A]): FP2Elem[A] = -x
      def zero: FP2Elem[A] = FP2Elem(fieldA.zero, fieldA.zero)
      def plus(x: FP2Elem[A], y: FP2Elem[A]): FP2Elem[A] = x + y
      def div(x: FP2Elem[A], y: FP2Elem[A]): FP2Elem[A] = x * y.inverse
      override def reciprocal(fp2: FP2Elem[A]): FP2Elem[A] = fp2.inverse
      def times(x: FP2Elem[A], y: FP2Elem[A]): FP2Elem[A] = x * y
      def one: FP2Elem[A] = FP2Elem(fieldA.zero, fieldA.one)
    }

  implicit def eq[A <: BigInt: Eq]: Eq[FP2Elem[A]] = Eq.instance {
    case (FP2Elem(x, y), FP2Elem(x2, y2)) => x2.eqv(x) && y2.eqv(y)
  }

  implicit def hashable[A <: BigInt: Hashable]: Hashable[FP2Elem[A]] = Hashable[(A, A)].contramap { case FP2Elem(elem1, elem2) => (elem1, elem2) }
  implicit def byteDecoderFP2Elem[A <: BigInt](implicit readA: BytesDecoder[A], modsByPrime: ModsByPrime[A]): BytesDecoder[FP2Elem[A]] =
    BytesDecoder.forSize(readA.acceptableSize * 2) { bytes =>
      val (first, second) = bytes.splitAt(bytes.length / 2)
      (readA.decode(first), readA.decode(second)).mapN { FP2Elem(_, _) }
    }
}
