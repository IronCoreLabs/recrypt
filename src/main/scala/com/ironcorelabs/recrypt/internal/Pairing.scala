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
import point.{ HomogeneousPoint }
import cats.Eq

class Pairing[FpType <: BigInt: Field: ExtensionField](implicit fpTypePairingConfig: PairingConfig[FpType], mods: ModsByPrime[FpType]) {
  //These are used in the frobenius method below
  val w: FP12Elem[FpType] = FP12Elem[FpType](Field[FP6Elem[FpType]].one, Field[FP6Elem[FpType]].zero) //w^2 = v
  private[this] val wSquared = w.square
  private[this] val wCubed = wSquared * w
  final val FrobeniusFactor1: FP12Elem[FpType] = wSquared.frobenius * wSquared.inverse
  final val FrobeniusFactor2: FP12Elem[FpType] = wCubed.frobenius * wCubed.inverse

  def frobenius(point: HomogeneousPoint[FP2Elem[FpType]])(implicit eqFpType: Eq[FpType]): HomogeneousPoint[FP2Elem[FpType]] = point match {
    case HomogeneousPoint(x, y, z) =>
      //Frobenius endomorphism of the twisted curve.  This will be used in the pairing.
      val newX = (FrobeniusFactor1 * x.frobenius).toFP2.getOrElse(throw new Exception(s"Cannot go to Fp2 for x on '$x'"))
      val newY = (FrobeniusFactor2 * y.frobenius).toFP2.getOrElse(throw new Exception(s"Cannot go to Fp2 for y on '$y'"))
      HomogeneousPoint(newX, newY, z.frobenius)
  }

  // Returns the value at p of the function whose zero-set is the line through q and r.
  // Script l with addition in the denominator from Miller's Algorithm
  // Used in step 6 or 8 of Algorithm 1 in High-Speed Software Implementation of the Optimal Ate Pairing over Barreto–Naehrig Curves
  def addLineEval(px: FpType, py: FpType, q: HomogeneousPoint[FP2Elem[FpType]], r: HomogeneousPoint[FP2Elem[FpType]]): (FP12Elem[FpType], FP2Elem[FpType]) = {
    val numerator = (r.y * q.z - q.y * r.z)
    val denominator = (r.x * q.z - q.x * r.z)
    finalizeEval(q, px, py, numerator, denominator)
  }
  //returns the value at P of the function whose zero-set is the line through Q and R.
  // Script l with multiplication in the denominator from Miller's Algorithm
  // Used in step 4 of Algorithm 1 in High-Speed Software Implementation of the Optimal Ate Pairing over Barreto–Naehrig Curves
  def doubleLineEval(px: FpType, py: FpType, r: HomogeneousPoint[FP2Elem[FpType]]): (FP12Elem[FpType], FP2Elem[FpType]) = {
    val numerator = r.x.square * 3
    val denominator = r.y * r.z * 2
    finalizeEval(r, px, py, numerator, denominator)
  }

  private def finalizeEval(q: HomogeneousPoint[FP2Elem[FpType]], px: FpType, py: FpType, numerator: FP2Elem[FpType], denominator: FP2Elem[FpType]) = {
    val zero = Field[FP2Elem[FpType]].zero
    val zerqFp = Field[FpType].zero
    (FP12Elem(
      FP6Elem(zero, q.x * numerator - q.y * denominator, -q.z * numerator * FP2Elem(zerqFp, px)),
      FP6Elem(zero, zero, q.z * denominator * FP2Elem(zerqFp, py))
    ), q.z * denominator)
  }

  //Final exponentiation: compute the value f^((p^12 - 1) / r). This maps f to one of the rth roots of unity.
  //The exponent is factored, which allows the computation to be done in two parts (each with several steps):
  //    The easy part, which consists entirely of calls to frobenius and inverse.
  //    The hard part, which involves expressing the exponent as a polynomial in x = 1868033.
  def finalExponentiation(initialF: FP12Elem[FpType]): FP12Elem[FpType] = { //scalastyle:off
    var f = initialF
    //Easy part
    //"Computing f^((p^6-1)(p^2+1))..."
    var g = 0.to(5).foldLeft(f) { case (acc, _) => acc.frobenius }
    f = g * f.inverse //  f = f^(p^6-1)
    f = f.frobenius.frobenius * f //  f = f^(p^2+1)

    //Hard part: compute f = f^((p^4 - p^2 + 1)/r) - Section 7 of Devegili Scott Dahab Pairings over BN curves - Algorithm 3
    //At this point, f has the convenient property that f^(p^6+1) == 1.
    //Thus, f^(-1) == f^p^6 == frobenius^6(f)
    //We also express the exponent as a polynomial in x=1868033.  See Section 7 and in particular Algorithm 3 in Devegili--Scott--Dahab "Implementing Pairings over Barreto--Naehrig Curves"
    //(p^4 - p^2 + 1)/r = p^3 + p^2(6t^2+1) + p(-36t^3-18t^2-12t+1) + (-36t^3-30t^2-18t-2), where t is the BNParam
    val fInv = f.conjugate // f is unitary (See explanation in Beuchet--Gonzalez-Diaz--Mitsunari et. al. bottom of page 4), so f^(-1) == \overline{f}
    g = fpTypePairingConfig.square(fInv) //g = f^(-2)
    g = fpTypePairingConfig.square(g) * g //g = g^3
    g = fpTypePairingConfig.bnPow(g) //g = g^x, where x = 1868033 = cube root of BNParam
    g = fpTypePairingConfig.bnPow(g) //g = g^x
    g = fpTypePairingConfig.bnPow(g) //g = g^x = f^(-6x^3)
    val a = g * fpTypePairingConfig.square(fpTypePairingConfig.square(fInv)) * fInv //a = f^-(6*x^3-5)
    var b = a.frobenius //b = a^p
    b = a * b //b = a^(p+1)
    val g1 = f.frobenius //g1 = f^p
    val g2 = g1.frobenius //g2 = g2^p
    val g3 = g2.frobenius //g3 = g2^p = f^(p^3)
    val g4 = b * fpTypePairingConfig.square(g1) * g2 //g4 = b*g1^2*g2
    var g5 = fpTypePairingConfig.square(g4) //g5 = g4^2
    g5 = fpTypePairingConfig.square(g5) * g5 //g5 = g5^3 = g4^6
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    g5 = fpTypePairingConfig.bnPow(g5) //g5^x
    val g6 = g1 * f
    g3 * g5 * g4 * b * fpTypePairingConfig.square(fpTypePairingConfig.square(fpTypePairingConfig.square(g6))) * g6 * a * fpTypePairingConfig.square(fpTypePairingConfig.square(f))
  } //scalastyle:on

  // This is the optimal Ate pairing, as introduced in the paper "The Eta Pairing Revisited" by
  // Hess, et al., from 2006. Our implementation is based on the paper "High-Speed Software
  // Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves" by Beuchat et al,
  // from 2010.
  def pair(pointPHPoint: HomogeneousPoint[FpType], pointQ: HomogeneousPoint[FP2Elem[FpType]])(implicit eqFpType: Eq[FpType]): FP12Elem[FpType] = {
    val (px, py) = pointPHPoint.normalize.getOrElse(throw new Exception("pair isn't defined with the zero point."))
    var f1 = Field[FP12Elem[FpType]].one
    var f2 = Field[FP2Elem[FpType]].one
    val negQ = pointQ.negate

    //The NAFforLoop is the Non adjacent form of the loopLength.
    val pointResult = fpTypePairingConfig.nafForLoop.foldLeft(pointQ) {
      case (accPoint, nafValue) =>
        var pointR = accPoint
        var pointS = pointR.double
        val (ell1, ell2) = doubleLineEval(px, py, pointR)
        f1 = ell1 * f1.square
        f2 = ell2 * f2.square
        pointR = pointS
        if (nafValue == -1) {
          pointS = negQ.add(pointR)
          val (ell1, ell2) = addLineEval(px, py, negQ, pointR)
          f1 *= ell1
          f2 *= ell2
          pointR = pointS
          pointR
        } else if (nafValue == 1) {
          pointS = pointQ.add(pointR)
          val (ell1, ell2) = addLineEval(px, py, pointQ, pointR)
          f1 *= ell1
          f2 *= ell2
          pointR = pointS
          pointR
        } else {
          pointR
        }
    }
    val pointQ1 = frobenius(pointQ)
    val pointQ2 = frobenius(pointQ1)
    val pointS = pointQ1.add(pointResult)
    val (ell1, ell2) = addLineEval(px, py, pointQ1, pointResult)
    f1 *= ell1
    f2 *= ell2
    val pointR = pointS
    val (ell3, ell4) = addLineEval(px, py, pointQ2.negate, pointR)
    f1 *= ell3
    f2 *= ell4
    val f = f1 * FP12Elem(Field[FP6Elem[FpType]].zero, FP6Elem(Field[FP2Elem[FpType]].zero, Field[FP2Elem[FpType]].zero, f2.inverse))
    finalExponentiation(f)
  }
}
