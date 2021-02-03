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
import spire.algebra.Field

/**
 * This type holds all the points that are used in our core algorithm for for `FpType`.
 *
 * g1 is the point which is in Fp2 and is used in the pairing.
 * hashElement is another point in Fp2 that is used for hashing.
 * generator is the generator point over FpType.
 */
final case class CurvePoints[FpType <: BigInt: ExtensionField: Field: ModsByPrime](
  g1: HomogeneousPoint[FP2Elem[FpType]],
  hashElement: HomogeneousPoint[FP2Elem[FpType]],
  generator: HomogeneousPoint[FpType]) {
  val publicKeyGen = new PublicKeyGen[FpType](generator)
}
