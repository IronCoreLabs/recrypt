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
package point
import spire.algebra.Field
import algebra.ring.AdditiveCommutativeGroup
import spire.implicits._
import cats.kernel.Eq
import scodec.bits.ByteVector
import cats.syntax.apply._
import cats.instances.either._
import cats.syntax.either._
import cats.syntax.contravariant._

object HomogeneousPoint {
  implicit def aGroup[A: Field: Eq]: AdditiveCommutativeGroup[HomogeneousPoint[A]] = new AdditiveCommutativeGroup[HomogeneousPoint[A]] {
    def plus(x: HomogeneousPoint[A], y: HomogeneousPoint[A]): HomogeneousPoint[A] = x.add(y)
    val zero: HomogeneousPoint[A] = {
      val aField = Field[A]
      new HomogeneousPoint(aField.zero, aField.one, aField.zero)
    }
    def negate(x: HomogeneousPoint[A]): HomogeneousPoint[A] = x.negate
  }
  implicit def eq[A](implicit aEq: Eq[A], field: Field[A]): Eq[HomogeneousPoint[A]] = Eq.instance {
    case (HomogeneousPoint(x, y, z), HomogeneousPoint(x1, y1, z1)) =>
      //This is to save doing inverses on z and z1. For equality we can instead do the multiplation instead.
      (aEq.eqv(z, z1) && aEq.eqv(x, x1) && aEq.eqv(y, y1)) || (aEq.eqv(x * z1, x1 * z) && aEq.eqv(y * z1, y1 * z))
  }

  /**
   * This is a stable hashable valuable which cannot be changed without breaking the compatibility of recrypt.
   */
  implicit def hashable[A](implicit A: Hashable[A]): Hashable[HomogeneousPoint[A]] = Hashable[Option[(A, A)]].contramap(_.normalize)

  //This will take 2 FP2Elem points which are concatenated.
  //If the point isn't on the curve or if the bytes didn't represent 2 FP2Elems, left. Otherwise Right(HomogeneousPoint[FP12Elem])
  def fromXYByteVectorOnTwistedCurve[A <: BigInt: BytesDecoder: Field: ExtensionField: Eq: ModsByPrime](
    bytes: ByteVector): Either[PointError, HomogeneousPoint[FP2Elem[A]]] = {
    val twistedCurveConstCoeff: FP2Elem[A] = implicitly[ExtensionField[A]].xi.reciprocal * 3 //  3 / (u + 3) //COLT: Should move to prime field maybe?
    val (first, second) = bytes.splitAt(bytes.size / 2)

    val candidateXY = (
      BytesDecoder[FP2Elem[A]].decode(first).leftMap(_ => InvalidCoordinate(first, "Bytes for x coordinate didn't represent an FP2Elem")),
      BytesDecoder[FP2Elem[A]].decode(second).leftMap(_ => InvalidCoordinate(first, "Bytes for y coordinate didn't represent a valid FP2Elem"))
    ).tupled

    candidateXY.flatMap {
      case (x, y) =>
        if (y.pow(2) === (x.pow(3) + twistedCurveConstCoeff))
          HomogeneousPoint[FP2Elem[A]](x, y, Field[FP2Elem[A]].one).asRight
        else
          PointNotOnCurve(x, y).asLeft
    }
  }

  def apply[A: Field: Eq](x: A, y: A): Either[PointError, HomogeneousPoint[A]] = {
    if (x.pow(3) + 3 == y.pow(2))
      withoutCurveValidation(x, y).asRight
    else
      PointNotOnCurve(x, y).asLeft
  }

  def withoutCurveValidation[A: Field: Eq](x: A, y: A): HomogeneousPoint[A] =
    HomogeneousPoint(x, y, Field[A].one)
}

/**
 * Point expressed by x,y,z such that if z is 0, the point is the zero point. Otherwise it is the point x/z, y/z in Affine coordinates.
 * Note that these values must themselves have an instance of the Field typeclass for this to be true.
 *
 * Note that this value is *not* verified to be on the curve. If you want to do that, it'll have to be done as part of the translation
 * for whatever A type the coordinate represents.
 */
final case class HomogeneousPoint[A] private (x: A, y: A, z: A)(implicit aField: Field[A], eqA: Eq[A]) {
  private[this] val ZeroA: A = aField.zero
  private[this] def zeroPoint: HomogeneousPoint[A] = HomogeneousPoint(aField.zero, aField.one, aField.zero)
  def negate: HomogeneousPoint[A] = HomogeneousPoint[A](x, -y, z)
  def double: HomogeneousPoint[A] = {
    if (isZero) {
      this
    } else if (y === ZeroA) {
      zeroPoint
    } else {
      val xCubed = x.pow(3)
      val ySquared = y.pow(2)
      val zSquared = z.pow(2)
      val ySquaredTimesZ = ySquared * z
      val eightTimesYsquaredTimesZ = 8 * ySquaredTimesZ
      val nineTimesXCubed = 9 * xCubed
      val x2 = 2 * x * y * z * (nineTimesXCubed - eightTimesYsquaredTimesZ)
      val y2 = nineTimesXCubed * (4 * ySquaredTimesZ - 3 * xCubed) - eightTimesYsquaredTimesZ * ySquaredTimesZ
      val z2 = eightTimesYsquaredTimesZ * y * zSquared
      HomogeneousPoint[A](x2, y2, z2)
    }
  }
  def add(p: HomogeneousPoint[A]): HomogeneousPoint[A] = {
    if (isZero) {
      p
    } else if (p.isZero) {
      this
    } else {
      p match {
        case HomogeneousPoint(x2, y2, z2) if x === x2 && y === -y2 && z === z2 => zeroPoint
        case h @ HomogeneousPoint(_, _, _) if h === this => double
        case HomogeneousPoint(x2, y2, z2) =>
          val yTimesZ2 = y * z2
          val xTimesZ2 = x * z2
          val x2TimesZ = x2 * z
          val a = (y2 * z) - yTimesZ2
          val b = x2TimesZ - xTimesZ2
          val zTimesZ2 = z * z2
          val bSquared = b.pow(2)
          val bCubed = bSquared * b
          val aSquared = a.pow(2)
          val zTimesZ2TimesASquared = zTimesZ2 * aSquared
          val xTimesZ2PlusX2TimesZ = xTimesZ2 + x2TimesZ
          val x3 = b * (zTimesZ2TimesASquared - (bSquared * xTimesZ2PlusX2TimesZ))
          val y3 = a * bSquared * (xTimesZ2 + xTimesZ2PlusX2TimesZ) - ((zTimesZ2TimesASquared * a) + (yTimesZ2 * bCubed))
          val z3 = zTimesZ2 * bCubed
          HomogeneousPoint[A](x3, y3, z3)
      }
    }
  }
  def times(multiple: BigInt): HomogeneousPoint[A] = {
    if (isZero) {
      this
    } else if (y === ZeroA) {
      this
    } else {
      val negSelf = negate
      // get multiple in NAF (this algorithm only works for positive numbers, hence the call to abs)
      val NAF = createNAF(multiple.abs)

      val result = NAF.reverse.foldLeft(zeroPoint) { (res, cur) =>
        val doubled = res.double
        if (cur === -1) doubled.add(negSelf) else if (cur === 1) doubled.add(this) else doubled
      }
      if (multiple < 0) {
        result.negate
      } else {
        result
      }
    }
  }

  def toByteVector(implicit h: Hashable[A]): ByteVector = {
    val zInv = Field[A].one / z
    h.toByteVector(x * zInv) ++ h.toByteVector(y * zInv)
  }

  def isZero: Boolean = z == ZeroA

  def normalize: Option[(A, A)] = {
    if (isZero) {
      None
    } else {
      val zInv = z.reciprocal
      Some((x * zInv, y * zInv))
    }
  }
}
