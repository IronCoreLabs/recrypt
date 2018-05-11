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

/**
 * This typeclass contains the values needed to configure a new Fp type to be used as an extension field (FP2Elem, FP6Elem, FP12Elem)
 */
trait ExtensionField[A <: BigInt] {
  // Xi is u + 3 which is v^3.
  // v^p == Xi^((p-1)/3) * v
  def xi: FP2Elem[A]

  // Used in frobenius, this is Xi^((p-1)/3)
  // Fp6Elem[A](Fp2Elem.Zero, Fp2Elem.One, Fp2Elem.Zero).frobenius
  //Xi  ^ ((p - p % 3) /3) because of the prime we've chosen, p % 3 == 1
  def frobeniusFactor1: FP2Elem[A]

  // Used in frobenius, this is frobeniusFactor1^2
  def frobeniusFactor2: FP2Elem[A]

  // if q = (p-1)/2
  // q % 3 == 0  -- For our p
  // Xi ^ ((q - q % 3)/3)
  def frobeniusFactorFp12: FP2Elem[A]
  /**
   * v is the thing that cubes to xi
   * v^3 = u+3, because by definition it is a solution to the equation y^3 - (u + 3)
   */
  def v: FP6Elem[A]
}
