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
import spire.implicits._
import cats.syntax.contravariant._

/**
 * An element of the degree 12 extension of our base finite field Fp. The degree 12 extension is formed on
 * the degree six extension using the substitution w^2 = v. That is, FP12 = FP6[w]/(w^2 - v)
 *
 * A value in FP12 is represented as a polynomial a + b * w, where a and b are both FP6Elems.
 *
 * Recall that v is the attached variable for FP6.
 */
final case class FP12Elem[A <: BigInt: ExtensionField: Field](elem1: FP6Elem[A], elem2: FP6Elem[A])(implicit mods: ModsByPrime[A]) { self =>
  private[this] val V = implicitly[ExtensionField[A]].v
  private[this] val FrobeniusFactor = implicitly[ExtensionField[A]].frobeniusFactorFp12

  def +(other: FP12Elem[A]): FP12Elem[A] = {
    val newFp1 = elem1 + other.elem1
    val newFp2 = elem2 + other.elem2
    FP12Elem[A](newFp1, newFp2)
  }

  def -(other: FP12Elem[A]): FP12Elem[A] = {
    val newFp1 = elem1 - other.elem1
    val newFp2 = elem2 - other.elem2
    FP12Elem[A](newFp1, newFp2)
  }

  def unary_- : FP12Elem[A] = FP12Elem[A](-elem1, -elem2) //scalastyle:ignore method.name

  def inverse: FP12Elem[A] = {
    //Algorithm 5.19 of El Mrabet--Joye 2017 "Guide to Pairing-Based Cryptography."
    val (b, a) = (elem1, elem2)
    val v0 = a.square
    val v1 = b.square
    val v00 = v0 - V * v1
    val v11 = v00.inverse
    val c0 = a * v11
    val c1 = -b * v11
    FP12Elem[A](c1, c0)
  }

  def *(other: FP12Elem[A]): FP12Elem[A] = {
    val (x1, x0) = (elem1, elem2)
    val (y1, y0) = (other.elem1, other.elem2)
    val z0 = x0 * y0
    val z2 = x1 * y1
    val z1 = (x1 + x0) * (y1 + y0)
    val w1 = z1 - z2 - z0
    val (z01, z02, z03) = (z0.elem1, z0.elem2, z0.elem3)
    val (z21, z22, z23) = (z2.elem1, z2.elem2, z2.elem3)
    FP12Elem[A](
      w1,
      FP6Elem.create(
        mods.create(z01.elem1 + z22.elem1),
        mods.create(z01.elem2 + z22.elem2),
        mods.create(z02.elem1 + z23.elem1),
        mods.create(z02.elem2 + z23.elem2),
        mods.create(z03.elem1 + z21.elem2 + (z21.elem1 * 3)),
        mods.create(z03.elem2 + (z21.elem2 * 3) - z21.elem1)
      )
    )
  }

  def *(other: FP2Elem[A]): FP12Elem[A] = {
    val (x1, x0) = (elem1, elem2)
    val y1 = x1 * other
    val y0 = x0 * other
    FP12Elem[A](y1, y0)
  }

  def ^(power: BigInt): FP12Elem[A] = {
    if (power == BigIntZero) {
      Field[FP12Elem[A]].one
    } else if (this == Field[FP12Elem[A]].zero) {
      Field[FP12Elem[A]].zero
    } else if (power < 0) {
      throw new Exception("Fp12 elements cannot be taken to negative powers.")
    } else {
      val bits = scodec.bits.BitVector(power.toByteArray).toIndexedSeq.dropWhile(!_)
      bits.foldLeft(Field[FP12Elem[A]].one) {
        case (cur, bit) =>
          val squareResult = cur.square
          if (bit) squareResult * this else squareResult
      }
    }
  }

  def conjugate: FP12Elem[A] = FP12Elem[A](-elem1, elem2)

  //This is the element to the p power.
  def frobenius: FP12Elem[A] = {
    val a = elem1.frobenius
    val b = elem2.frobenius
    val newElem1 = a * FrobeniusFactor
    FP12Elem[A](newElem1, b)
  }

  def square: FP12Elem[A] = {
    val a2 = elem1 * elem2 * 2
    val b2 = elem1.square * V + elem2.square
    FP12Elem[A](a2, b2)
  }

  def toFP2: Option[FP2Elem[A]] = elem2.toFP2

  override def toString: String = {
    s"(($elem1) * w + ($elem2))"
  }
}

object FP12Elem {
  def create[A <: BigInt: ExtensionField: Field: ModsByPrime](fp1: A, fp2: A, fp3: A, fp4: A, //scalastyle:ignore parameter.number - Need to take all 12.
    fp5: A, fp6: A, fp7: A, fp8: A, fp9: A, fp10: A, fp11: A, fp12: A): FP12Elem[A] = FP12Elem[A](
    FP6Elem.create[A](fp1, fp2, fp3, fp4, fp5, fp6),
    FP6Elem.create[A](fp7, fp8, fp9, fp10, fp11, fp12)
  )

  implicit def field[A <: BigInt: ExtensionField: Field: ModsByPrime]: Field[FP12Elem[A]] = new Field[FP12Elem[A]] {
    val fp6Zero = Field[FP6Elem[A]].zero
    def negate(x: FP12Elem[A]): FP12Elem[A] = -x
    val zero: FP12Elem[A] = FP12Elem[A](fp6Zero, fp6Zero)
    def plus(x: FP12Elem[A], y: FP12Elem[A]): FP12Elem[A] = x + y
    def div(x: FP12Elem[A], y: FP12Elem[A]): FP12Elem[A] = x * y.inverse
    def times(x: FP12Elem[A], y: FP12Elem[A]): FP12Elem[A] = x * y
    val one: FP12Elem[A] = FP12Elem[A](fp6Zero, Field[FP6Elem[A]].one)
  }

  implicit def eq[A <: BigInt: Eq]: Eq[FP12Elem[A]] = Eq.instance {
    case (FP12Elem(one, two), FP12Elem(onePrime, twoPrime)) =>
      one === onePrime && two === twoPrime
  }

  implicit def hashable[A <: BigInt: Hashable]: Hashable[FP12Elem[A]] =
    Hashable[(FP6Elem[A], FP6Elem[A])].contramap { case FP12Elem(elem1, elem2) => elem1 -> elem2 }

  /* Converting to a byte vector just concatenates the byte vector representation of each
   * of the two coefficients a and b . So reversing just requires splitting the byte vector
   * in half and converting each smaller vector back to an element.
   * (Note that this is recursive, since the coefficients are each FP6 elements, which
   * consist of three coefficients.)
   */

  implicit def byteDecoderFP12Elem[A <: BigInt: ModsByPrime](implicit
    readFp6A: BytesDecoder[FP6Elem[A]],
    fieldA: Field[A],
    primeFieldA: ExtensionField[A]): BytesDecoder[FP12Elem[A]] = BytesDecoder.forSize(readFp6A.acceptableSize * 2) { b =>
    val (first, second) = b.splitAt(b.length / 2)
    for {
      elem1 <- readFp6A.decode(first)
      elem2 <- readFp6A.decode(second)
    } yield FP12Elem[A](elem1, elem2)
  }
}
