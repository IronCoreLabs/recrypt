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

import scodec.bits.ByteVector
import cats.syntax.either._

/**
 * A value (which is a point on the elliptic curve in the extension field) and is valid by construction.
 * bytes - Concatenated bytes of the 2 FP2Elems that make up the point.
 */
sealed abstract case class HashedValue(bytes: ByteVector) {
  private[recrypt] def internalPoint: internal.point.HomogeneousPoint[internal.FP2Elem[internal.Fp]]
}
object HashedValue {
  implicit val hashable: Hashable[HashedValue] = Hashable.by(_.bytes)

  def apply(bytes: ByteVector): Either[ApiError, HashedValue] = {
    import internal.Fp.implicits._
    internal.point.HomogeneousPoint.fromXYByteVectorOnTwistedCurve(bytes).leftMap[ApiError] {
      case internal.PointNotOnCurve(_, _) => InvalidHashedValue("HashedValue was not a valid point on the curve.")
      case internal.InvalidCoordinate(_, _) => InvalidHashedValue("HashedValue was not the correct length.")
    }.map(iPoint => new HashedValue(iPoint.toByteVector) { val internalPoint = iPoint })
  }
}
