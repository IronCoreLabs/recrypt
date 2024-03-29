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

import cats.kernel.Eq
import scodec.bits.ByteVector
import spire.algebra.Field
import cats.syntax.either._

/**
 * Fp represents a value in the field of integers mod some Prime - that is, values in [0, Prime - 1].
 *
 * This is a pattern that is laid out by https://failex.blogspot.com/2017/04/and-glorious-subst-to-come.html
 * The idea is that `Fp` is a type alias for some dependent type on a singleton "Impl.T", which
 * is just a subtype of BigInt.
 *
 * We get the guarantees about Fp's safety by modding anytime someone calls the apply on the companion
 * object, but without any runtime allocations.
 */
final object Fp {
  def apply(x: BigInt): Impl.T = Impl(x)
  def apply(b: ByteVector): Impl.T = Impl(b)
  trait BigIntImpl {
    type T <: BigInt
    def apply(x: BigInt): T
    def apply(b: ByteVector): T
  }

  val Impl: BigIntImpl = new BigIntImpl {
    type T = BigInt
    def apply(x: BigInt): T = positiveMod(x, Prime)
    def apply(b: ByteVector): T = apply(byteVectorToBigInt(b))
  }

  //For info on the Algorithm, etc. Please refer to Fp.scala.
  //BNParam for this is
  final val Prime = BigInt("65000549695646603732796438742359905742825358107623003571877145026864184071783")
  final val Order = BigInt("65000549695646603732796438742359905742570406053903786389881062969044166799969")
  val Zero = Fp(BigIntZero)
  val One = Fp(BigIntOne)

  //The leading byte is a 0 since Prime is positive, we don't want that in all the sizes.
  val ExpectedFpLength: Long = Prime.toByteArray.length - 1L
  val ExpectedOrderLength: Long = Order.toByteArray.length - 1L

  /**
   * inverse mod a prime is always in Fp, so the cast is safe.
   */
  def inverseModPrime(fp: Fp): Fp = inverse(fp, Prime).getOrElse(Fp.Zero).asInstanceOf[Fp]
  /**
   * Only call this if `i` is very close to the Prime, otherwise it will be inefficient.
   */
  @annotation.tailrec
  def fastModPrime(i: BigInt): Fp = {
    if (i >= Fp.Prime) {
      fastModPrime(i - Prime)
    } else {
      Fp(i)
    }
  }

  def bigIntToByteVector(b: BigInt): ByteVector = {
    val zeroByte = 0.toByte
    val byteVector = ByteVector.view(b.toByteArray)
    //Drop the leading zero if there is one (Because this value is positive.) Then make sure that the
    //byteVector is padded out to ExpectedFpLength
    byteVector.dropWhile(_ == zeroByte).padLeft(ExpectedFpLength)
  }

  lazy val curvePoints: CurvePoints[Fp.Impl.T] = {
    import implicits._
    CurvePoints(
      // Fixed point in cyclic group G1 (the trace zero subgroup).
      //   Start with a point that is on the twisted curve y^2 = x^3 + (3 / (u + 3)).
      //   Turns out u + 1 is a valid x, with y = sqrt(x^3 + (3 / (u + 3)).
      //   Take (x,y) and multiply by (p + p - r) to get an r-torsion element of the twisted curve over FP2.
      //   Compute the anti-trace map of that r-torsion element to get a point in the trace-zero subgroup.
      point.HomogeneousPoint[FP2Elem[Fp]](
        FP2Elem(
          Fp(BigInt("25743265030535080187440590897139396943782163562799308681850377411492232521347")),
          Fp(BigInt("34056889713323967780338301808336650802977437253339894663986165323395183925712"))
        ),
        FP2Elem(
          Fp(BigInt("36332093629799712472233840570439767783123758424653318224159027848500552319214")),
          Fp(BigInt("19100300358747584658695151329066047798696640594509146799364306658205997167318"))
        ),
        FP2Elem(
          Fp(BigInt("11969434517458907073927619028753373626677015846219303340439317866996854601254")),
          Fp(BigInt("14774454666095297364611775449425506027744765805321334870185419948913527571534"))
        )
      ),
      // Used to hash integers to a point in FP2
      // Generated by multiplying g1 by the SHA256 hash of the date/time "Mon Feb 19 16:30:21 MST 2018\n",
      // encoded in ASCII/UTF-8, converted to a BigInt.
      point.HomogeneousPoint[FP2Elem[Fp]](
        FP2Elem(
          Fp(BigInt("26115920809144023111516349163868890892335785984202627188956566235163006540541")),
          Fp(BigInt("15905362109061908101726321997764649315090633150407344591241408991746779381256"))
        ),
        FP2Elem(
          Fp(BigInt("4632230948348518150642153940906247958418069554996068756252789717528925762701")),
          Fp(BigInt("3026141039160762752629025637420408604709576372807872293769066469244216243501"))
        ),
        FP2Elem(
          Fp(BigInt("43872202626887887868122322275088633257981831137687656289783477940483447530228")),
          Fp(BigInt("20191379131685497308054970475671582162258136917730106438050079114233947942452"))
        )
      ),
      point.HomogeneousPoint(Fp(1), Fp(2), Fp(1))
    )
  }

  //Object which contains the implicits for Fp.
  final object implicits { // scalastyle:ignore object.name
    implicit val hashableFp: Hashable[Fp.Impl.T] = Hashable.by(bigIntToByteVector)
    implicit val fpEq: Eq[Fp.Impl.T] = Eq.fromUniversalEquals
    implicit val fieldForFp: Field[Fp.Impl.T] = new Field.WithDefaultGCD[Fp] {
      //These casts are safe because they shouldn't ever produce something that is
      //not in Fp. This is demonstrated in unit tests, but not statically.
      def negate(x: Fp): Fp = if (x == Fp.Zero) Fp.Zero else (Fp.Prime - x).asInstanceOf[Fp]
      val zero: Fp = Fp.Zero
      def plus(x: Fp, y: Fp): Fp = fastModPrime(x + y)
      def times(x: Fp, y: Fp): Fp = Fp(x * y)
      def div(x: Fp, y: Fp): Fp = Fp(x * Fp.inverseModPrime(y))
      override def reciprocal(fp: Fp): Fp = Fp.inverseModPrime(fp)
      val one: Fp = Fp.One
    }

    implicit val modsByPrimeFp: ModsByPrime[Fp.Impl.T] = new ModsByPrime[Fp] {
      def create(i: BigInt): Fp = Fp(i)
      def create(b: ByteVector): Fp = Fp(b)
      val prime: BigInt = Fp.Prime
    }

    implicit val extensionField: ExtensionField[Fp.Impl.T] = new ExtensionField[Fp.Impl.T] {
      val xi: FP2Elem[Fp.Impl.T] = FP2Elem(Fp(1), Fp(3))
      val frobeniusFactor1: FP2Elem[Fp.Impl.T] = FP2Elem(
        Fp(BigInt("26098034838977895781559542626833399156321265654106457577426020397262786167059")),
        Fp(BigInt("15931493369629630809226283458085260090334794394361662678240713231519278691715"))
      )
      val frobeniusFactor2: FP2Elem[Fp.Impl.T] = FP2Elem(
        Fp(BigInt("19885131339612776214803633203834694332692106372356013117629940868870585019582")),
        Fp(BigInt("21645619881471562101905880913352894726728173167203616652430647841922248593627"))
      )
      val frobeniusFactorFp12: FP2Elem[Fp.Impl.T] = FP2Elem(
        Fp(BigInt("8669379979083712429711189836753509758585994370025260553045152614783263110636")),
        Fp(BigInt("19998038925833620163537568958541907098007303196759855091367510456613536016040"))
      )
      val v: FP6Elem[Fp.Impl.T] = FP6Elem(Field[FP2Elem[Fp]].zero, Field[FP2Elem[Fp]].one, Field[FP2Elem[Fp]].zero)
    }

    implicit val pairingConfigFp: PairingConfig[Fp.Impl.T] = new PairingConfig[Fp.Impl.T] {
      //NAF of 6*BNParam + 2
      private[this] val NAF = IndexedSeq(0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0) //scalastyle:ignore
      // The reason we drop(2) is because of Algorithm 1 in High-Speed Software Implementation of the Optimal Ate Pairing over Barreto–Naehrig Curves
      val nafForLoop: IndexedSeq[Int] = NAF.reverse.drop(2)
      //This is based on the BNParam. It's the cuberoot of BNParam. It should always be called
      //in multiples of 3.
      def bnPow(self: FP12Elem[Fp.Impl.T]): FP12Elem[Fp.Impl.T] = {
        //This is a hardcode of the square and multiply for bnPow
        var x = self
        var res = x
        1.to(8).foreach(_ => x = square(x))
        res = res * x
        1.to(7).foreach(_ => x = square(x))
        res = res * x
        1.to(3).foreach(_ => x = square(x))
        res = res * x.conjugate
        1.to(3).foreach(_ => x = square(x))
        res * x
      }
    }

    implicit val bytesDecoder: BytesDecoder[Fp.Impl.T] = BytesDecoder.forSize(ExpectedFpLength.toInt) { bytes =>
      Fp(bytes).asRight
    }
  }
}
