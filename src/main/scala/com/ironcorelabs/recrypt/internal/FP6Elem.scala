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
import cats.syntax.eq._
import cats.syntax.contravariant._

/**
 * This is the degree 6 extension of the base field, which is formed on top of the degree 2 extension
 * using the variable substitution v^3 = u + 3. That factor, u + 3, is also referred to as Xi.
 * A value in FP6 is represented as a polynomial a + b * v + c * v^2, where a, b, and c are all
 * FP2Elems. That is, FP6 = FP2[v]/(v^3 - (u + 3)).
 *
 * Recall that u is the attached variable for FP2.
 */
final case class FP6Elem[A <: BigInt: ModsByPrime](elem1: FP2Elem[A], elem2: FP2Elem[A], elem3: FP2Elem[A]) {
  def +(other: FP6Elem[A]): FP6Elem[A] = {
    val newFp1 = elem1 + other.elem1
    val newFp2 = elem2 + other.elem2
    val newFp3 = elem3 + other.elem3
    FP6Elem[A](newFp1, newFp2, newFp3)
  }

  def -(other: FP6Elem[A]): FP6Elem[A] = {
    val newFp1 = elem1 - other.elem1
    val newFp2 = elem2 - other.elem2
    val newFp3 = elem3 - other.elem3
    FP6Elem[A](newFp1, newFp2, newFp3)
  }

  def unary_- : FP6Elem[A] = FP6Elem[A](-elem1, -elem2, -elem3) //scalastyle:ignore

  def *(other: FP6Elem[A])(implicit extensionField: ExtensionField[A]): FP6Elem[A] = {
    val Xi = implicitly[ExtensionField[A]].xi
    /*
     * We're multiplying 2 expressions of the following form:
     * a1*v^2 + b1 * v + c1  and a2*v^2 + b2 * v + c2 where
     * v^3 == xi and
     * a1 == fp1,
     * a2 == elem.fp1,
     * b1 == fp2,
     * b2 == elem.fp2
     * c1 == fp3
     * c2 == elem.fp3
     */
    val newElem1 = elem1 * other.elem3 + elem2 * other.elem2 + elem3 * other.elem1
    val newElem2 = elem1 * other.elem1 * Xi + elem2 * other.elem3 + elem3 * other.elem2
    val newElem3 = (elem1 * other.elem2 + elem2 * other.elem1) * Xi + elem3 * other.elem3
    FP6Elem[A](newElem1, newElem2, newElem3)
  }

  def *(other: FP2Elem[A]): FP6Elem[A] = {
    val a2 = elem1 * other
    val b2 = elem2 * other
    val c2 = elem3 * other
    FP6Elem[A](a2, b2, c2)
  }

  def inverse(implicit extensionField: ExtensionField[A]): FP6Elem[A] = {
    val Xi = implicitly[ExtensionField[A]].xi
    // Algorithm 5.23 from El Mrabet--Joye 2017 "Guide to Pairing-Based Cryptography."
    val (c, b, a) = (elem1, elem2, elem3)
    val v0 = a.square
    val v1 = b.square
    val v2 = c.square
    val v3 = a * b
    val v4 = a * c
    val v5 = b * c
    val A = v0 - Xi * v5
    val B = Xi * v2 - v3
    val C = v1 - v4
    val v6 = a * A
    val v61 = v6 + (Xi * c * B)
    val v62 = v61 + (Xi * b * C)
    val F = v62.inverse
    val c0 = A * F
    val c1 = B * F
    val c2 = C * F
    FP6Elem[A](c2, c1, c0)
  }

  //This is the element to the p power.
  //a^p + (b^p * v^p) + c^p *(v^p)^2
  // v^p == (v ^(p % 3)) * Xi  ^ ((p - p % 3) /3)
  def frobenius(implicit extensionField: ExtensionField[A]): FP6Elem[A] = {
    val frobeniusFactor1 = extensionField.frobeniusFactor1
    val frobeniusFactor2 = extensionField.frobeniusFactor2
    val a = elem1.frobenius
    val b = elem2.frobenius
    val c = elem3.frobenius
    val a1 = a * frobeniusFactor2
    val b1 = b * frobeniusFactor1
    FP6Elem[A](a1, b1, c)
  }

  def square(implicit extensionField: ExtensionField[A]): FP6Elem[A] = {
    val Xi = implicitly[ExtensionField[A]].xi
    val a_prime = FP2Elem.fromBigInts[A](elem1.elem1 * 2, elem1.elem2 * 2)
    val a2 = a_prime * elem3 + elem2.square
    val fp22 = elem1.square * Xi + elem2 * elem3 * 2
    val fp32 = (a_prime * elem2) * Xi + elem3.square
    FP6Elem[A](a2, fp22, fp32)
  }

  def toFP2(implicit fieldA: Field[A]): Option[FP2Elem[A]] = {
    val fp2Zero = Field[FP2Elem[A]].zero
    if (elem1 != fp2Zero || elem2 != fp2Zero) None else Some(elem3)
  }

  override def toString: String = s"($elem1)*v^2 + ($elem2)*v + ($elem3)"
}

object FP6Elem {
  def create[A <: BigInt: ModsByPrime](a: A, b: A, a2: A, b2: A, a3: A, b3: A): FP6Elem[A] =
    FP6Elem[A](FP2Elem[A](a, b), FP2Elem[A](a2, b2), FP2Elem[A](a3, b3))

  implicit def field[A <: BigInt: Field: ExtensionField: ModsByPrime]: Field[FP6Elem[A]] = new Field[FP6Elem[A]] {
    def negate(x: FP6Elem[A]): FP6Elem[A] = -x
    val zero: FP6Elem[A] = {
      val fp2Zero = Field[FP2Elem[A]].zero
      FP6Elem[A](fp2Zero, fp2Zero, fp2Zero)
    }
    def plus(x: FP6Elem[A], y: FP6Elem[A]): FP6Elem[A] = x + y
    def div(x: FP6Elem[A], y: FP6Elem[A]): FP6Elem[A] = x * y.inverse
    def times(x: FP6Elem[A], y: FP6Elem[A]): FP6Elem[A] = x * y
    val one: FP6Elem[A] = {
      val fp2Zero = Field[FP2Elem[A]].zero
      val fp2One = Field[FP2Elem[A]].one
      FP6Elem[A](fp2Zero, fp2Zero, fp2One)
    }
  }

  implicit def eq[A <: BigInt: Eq]: Eq[FP6Elem[A]] = Eq.instance {
    case (FP6Elem(one, two, three), FP6Elem(onePrime, twoPrime, threePrime)) =>
      one === onePrime && two === twoPrime && three === threePrime
  }

  implicit def hashable[A <: BigInt: Hashable]: Hashable[FP6Elem[A]] = Hashable[(FP2Elem[A], FP2Elem[A], FP2Elem[A])].contramap {
    case FP6Elem(elem1, elem2, elem3) => (elem1, elem2, elem3)
  }

  /* Converting to a byte vector just concatenates the byte vector representation of each
   * of the three coefficients a, b, and c together. So reversing just requires splitting
   * the byte vector in thirds and converting each smaller vector back to an element.
   * (Note that this is recursive, since the coefficients are each FP2 elements, which
   * in turn consist of two coefficients.)
   */
  implicit def byteDecoderFP6Elem[A <: BigInt: ModsByPrime](implicit readFp2A: BytesDecoder[FP2Elem[A]]): BytesDecoder[FP6Elem[A]] =
    BytesDecoder.forSize(readFp2A.acceptableSize * 3) { b =>
      val thirdLength = b.length / 3
      val (firstThird, twoThirds) = b.splitAt(thirdLength)
      val (secondThird, lastThird) = twoThirds.splitAt(thirdLength)
      for {
        elem1 <- readFp2A.decode(firstThird)
        elem2 <- readFp2A.decode(secondThird)
        elem3 <- readFp2A.decode(lastThird)
      } yield FP6Elem[A](elem1, elem2, elem3)
    }
}
