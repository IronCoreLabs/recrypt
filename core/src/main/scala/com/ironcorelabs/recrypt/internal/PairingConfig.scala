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

import spire.implicits._
import spire.algebra.Field

/**
 * This type represents the infomation to configure the pairing for a particular FpType.
 */
abstract class PairingConfig[FpType <: BigInt] {
  def square(fp12: FP12Elem[FpType])(implicit extension: ExtensionField[FpType], field: Field[FpType], mods: ModsByPrime[FpType]): FP12Elem[FpType] = {
    // Squaring for use in final exponentiation.  Shortcut taken from Section 3 of Granger--Scott
    // "Faster Squaring in the Cyclomatic Subgroup of Sixth Degree Extensions"
    val FP12Elem(b, a) = fp12
    val a2 = a * b * 2
    val b2 = b.square * 2
    val FP6Elem(z, y, x) = b2
    val z2 = z * extension.xi + 1
    FP12Elem[FpType](a2, FP6Elem(y, x, z2))
  }
  /**
   * raising of the fp12 to the cuberoot of the BNParam for FpType.
   * This is usually a hand optimized version of the square and multiply.
   */
  def bnPow(fp12: FP12Elem[FpType]): FP12Elem[FpType]
  /**
   * The naf which is used for the miller loop. In both our cases it's the NAF of 6*BNParam + 2 reversed with the last 2 dropped off.
   */
  def nafForLoop: IndexedSeq[Int]
}
