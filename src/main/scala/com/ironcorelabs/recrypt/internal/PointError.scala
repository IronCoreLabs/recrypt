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

import scodec.bits.ByteVector
sealed abstract class PointError

/**
 * Affine Point doesn't fulfill the curve equation.
 */
final case class PointNotOnCurve[A](x: A, y: A) extends PointError

/**
 * The coordinates couldn't even be decoded.
 */
final case class InvalidCoordinate(coordinate: ByteVector, reason: String) extends PointError
