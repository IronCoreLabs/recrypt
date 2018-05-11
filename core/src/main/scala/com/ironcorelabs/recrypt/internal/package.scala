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

package com.ironcorelabs.recrypt

import cats.data.NonEmptyVector
/**
 * Internal is a namespace that houses all the internal types and algorithms for the implementation. This is not meant to be
 * used by public consumers of recrypt.
 */
package object internal {
  final val BigIntZero = new BigInt(java.math.BigInteger.ZERO)
  final val BigIntOne = new BigInt(java.math.BigInteger.ONE)
  final val BigIntTwo = BigInt(2)
  final val BigIntFour = BigInt(4)

  /**
   * Compute the inverse of g mod m. Will be None if the g and m are not relatively prime.
   */
  def inverse(g: BigInt, m: BigInt): Option[BigInt] = {
    val (x, _, d) = gcde(g, m)
    if (d > BigIntOne) None else Some(positiveMod(x, m))
  }

  /**
   * This mod gives the *mod*, which isn't the same as the remainder (which is what `%` returns in Java).
   */
  def positiveMod(i: BigInt, m: BigInt): BigInt = {
    val x = i % m
    if (x < BigIntZero) x + m else x
  }

  def divMod(a: BigInt, b: BigInt): (BigInt, BigInt) = a / b -> positiveMod(a, b)

  /**
   * Get the extended GCD of two BigInts using integer divMod.
   * gcde 'a' 'b' find (x,y,gcd(a,b)) where ax + by = d
   */
  def gcde(a: BigInt, b: BigInt): (BigInt, BigInt, BigInt) = {
    @annotation.tailrec
    def f(t: (BigInt, BigInt, BigInt), t1: (BigInt, BigInt, BigInt)): (BigInt, BigInt, BigInt) = (t, t1) match {
      case (t, (BigIntZero, _, _)) => t
      case ((a1, sa, ta), t @ (b1, sb, tb)) =>
        val (q, r) = divMod(a1, b1)
        f(t, (r, sa - (q * sb), ta - (q * tb)))
    }
    val (d, x, y) = f((a, BigIntOne, BigIntZero), (b, BigIntZero, BigIntOne))
    (x, y, d)
  }

  /**
   * Modeled after sage's nbits. Returns the number of bits in the integer where the first bit was a 1. In the case of a
   * negative number, the bit count is of the positive number. This is to match what sage's nbits does.
   * E.g nbits(9) == 4, nbits(63) == 6
   * @param i - BigInt to get the bits for.
   * @return Number of bits with no leading zeros
   */
  def nbits(i: BigInt): Int = scodec.bits.BitVector.view(i.abs.toByteArray).toIndexedSeq.dropWhile(x => !x).length

  /**
   * Create a Non-Adjacent form of the value.
   * @param value - Integral value to convert to NAF.
   * @return - Immutable vector which represents the NAF of value.
   */
  def createNAF(value: BigInt): Vector[Int] = {
    //Mutable collection which has all 0s in it.
    val naf = scala.collection.mutable.IndexedSeq.fill(nbits(value) + 1)(0)
    var i = 0
    var n = value

    while (n > 0) {
      if (n % BigIntTwo != 0) {
        naf(i) = (BigIntTwo - (n % BigIntFour)).toInt
        n -= naf(i)
      } else {
        n /= BigIntTwo
        i += 1
      }
    }
    naf.toVector
  }

  //We assume the byteVector is meant to represent a positive integer.
  def byteVectorToBigInt(b: scodec.bits.ByteVector): BigInt = BigInt((0.toByte +: b).toArray)

  /**
   * Construct a NonEmptyVector from a possibly empty vector and a NonEmptyVector.
   */
  def fromVectorAndNonEmpty[A](v: Vector[A], nonEmptyVector: NonEmptyVector[A]): NonEmptyVector[A] =
    NonEmptyVector.fromVector(v).map(_ ++ nonEmptyVector.toVector).getOrElse(nonEmptyVector)

  type Fp = Fp.Impl.T
  type Fp480 = Fp480.Impl.T
}
