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
import cats.kernel.Eq
import Arbitraries._
import Fp.implicits._
import org.scalacheck.Arbitrary
import spire.algebra.Field

class HomogeneousPointTest extends com.ironcorelabs.recrypt.TestBase {
  val generator = HomogeneousPoint[Fp](Fp(1), Fp(2), Fp(1))
  val g2 = HomogeneousPoint[Fp](Fp(BigInt("65000549695646603732796438742359905742825358107623003571877145026864184071691")), Fp(BigInt("65000549695646603732796438742359905742825358107623003571877145026864184071772")), Fp(BigInt("64")))
  val g3 = HomogeneousPoint[Fp](Fp(BigInt("65000549695646603732796438742357289393463195703644999101259116053171121198695")), Fp(BigInt("4687415513658244809525991071247988106440212480")), Fp(BigInt("65000549695646603732796438742357781093930617575615238062101372432637196015207")))
  val g4 = HomogeneousPoint[Fp](Fp(BigInt("65000549695646603732796438742359905742825358107623003571877145025948345898599")), Fp(BigInt("65000549695646603732796438742359905742825358107623003571877145010275033523815")), Fp(BigInt("65000549695646603732796438742359905742825358107623003571877145026861392762471")))
  val homogeneousPointEq = Eq[HomogeneousPoint[Fp]]
  implicit val fpArb = Arbitrary(fpGen)

  "normalize" should {
    "go to None if HomogeneousPoint is zero" in {
      HomogeneousPoint(Fp(1), Fp(2), Fp(0)).normalize shouldBe None
    }
    "go to known point" in {
      HomogeneousPoint(Fp(10), Fp(20), Fp(2)).normalize.value shouldBe (Fp(5) -> Fp(10))
    }
  }

  "distributive law" should {
    "hold if sum is greater than R torsion" in {
      val expectedResult = generator.times(Fp.Order + 10)
      homogeneousPointEq.eqv(generator.times(Fp.Order).add(generator.times(10)), expectedResult) shouldBe true
    }
  }

  "toByteVector" should {
    val fp2ElemZero = Field[FP2Elem[Fp]].zero
    "always roundtrip with fromXYByteVector" in {
      val zeroPoint = HomogeneousPoint[FP2Elem[Fp]](fp2ElemZero, fp2ElemZero, fp2ElemZero)
      //fromXYByteVector results in a normalized version
      forAll { (one: HomogeneousPoint[FP2Elem[Fp]]) =>
        Eq[HomogeneousPoint[FP2Elem[Fp]]].eqv(HomogeneousPoint.fromXYByteVectorOnTwistedCurve(one.toByteVector).getOrElse(zeroPoint), one) shouldBe true
      }
    }
  }

  "addition to self" should {
    "be same as times(2) and double" in {
      val computedG2 = generator.add(generator)
      computedG2 shouldBe generator.double
      computedG2 shouldBe generator.times(2)
      computedG2 shouldBe g2
    }
    "be known computed points" in {
      generator.times(3) shouldBe g3
      //because they're generated different ways they z value is different.
      homogeneousPointEq.eqv(generator.add(generator).add(generator), g3) shouldBe true

      generator.double.double shouldBe g4
      generator.times(4) shouldBe g4
    }
  }

  "negate" should {
    "be inverse" in {
      val p = HomogeneousPoint[Fp](Fp(BigInt("51868263261043312406854161881216729836664278127733745592824683284523123334836")), Fp(BigInt("33177037179116331804302795932430957042199370361710027222382691374266461254686")), Fp(1))
      p.add(p.negate).isZero shouldBe true
    }
  }
  "FP2Elem" should {
    val generator = HomogeneousPoint[FP2Elem[Fp]](
      FP2Elem(Fp(BigInt("39898887170429929807040143276261848585078991568615066857293752634765338134660")), Fp(BigInt("4145079839513126747718408015399244712098849008922890496895080944648891367549"))),
      FP2Elem(Fp(BigInt("54517427188233403272140512636254575372766895942651963572804557077716421872651")), Fp(BigInt("29928198841033477396304275898313889635561368630804063259494165651195801046334"))),
      FP2Elem(Fp(BigInt("25757029117904574834370194644693146689936696995375576562303493881177613755324")), Fp(BigInt("20317563273514500379895253969863230147776170908243485486513578790623697384796")))
    )
    val g2 = HomogeneousPoint[FP2Elem[Fp]](
      FP2Elem(Fp(BigInt("32311960366087947012076758362581520145717417890234046373304260108936423529098")), Fp(BigInt("35269620335705756074126918480452007394637574429548402586405603689111865012277"))),
      FP2Elem(Fp(BigInt("2671623292902381891983929407252968557708719845514875421467184727609122988155")), Fp(BigInt("43411962343069999753626042779984151944324217242944227801565084354101193342512"))),
      FP2Elem(Fp(BigInt("49224387566402035134179552391576133560012154182767147936960003073581543401731")), Fp(BigInt("25130345353334486611452031924738614968497575666203626401540449736117460133315")))
    )
    val g3 = HomogeneousPoint[FP2Elem[Fp]](
      FP2Elem(Fp(BigInt("51086982105523813823110808607809625268338972497063497406133847490229508299200")), Fp(BigInt("52234782886912211912712112378454173535403665704601063483058173875683915331983"))),
      FP2Elem(Fp(BigInt("59006560018688086896657059684288540317025716993375680687355515288698643930005")), Fp(BigInt("32303626048328539612706779190102637076875855563268472072440283570203880314879"))),
      FP2Elem(Fp(BigInt("9132775622516916950536114990103670069586282707156393447180163663038647337412")), Fp(BigInt("11493687929025082100322220798309089712792846582945108156599613143240527668028")))
    )
    val eq = Eq[HomogeneousPoint[FP2Elem[Fp]]]
    "have g + g == g*2 " in {
      val result = generator.add(generator)
      eq.eqv(result, generator.times(2)) shouldBe true
      eq.eqv(result, g2) shouldBe true
    }
    "have g + g + g == g*3 " in {
      val result = generator.add(generator).add(generator)
      eq.eqv(result, g3) shouldBe true
      eq.eqv(result, generator.times(3)) shouldBe true
    }

    "have sane inverse" in {
      generator.add(generator.negate).isZero shouldBe true
    }

    "have known good frobenius" in {
      val expectedResult = HomogeneousPoint(
        FP2Elem(
          Fp(BigInt("3493288303413595898714519891264492301560207456168827437424957567620529428904")),
          Fp(BigInt("57579932449471156509924950033302853001562583061231887808723506993246370069786"))
        ),
        FP2Elem(
          Fp(BigInt("51856762088277527784977807176637663292245671912163591131470367010215157555522")),
          Fp(BigInt("49397214075582907890167267499315856190388550710652209341826106816887973948785"))
        ),
        FP2Elem(
          Fp(BigInt("39243520577742028898426244097666759052888661112247427009573651145686570316459")),
          Fp(BigInt("20317563273514500379895253969863230147776170908243485486513578790623697384796"))
        )
      )
      new Pairing[Fp].frobenius(generator) shouldBe expectedResult
    }
  }
}
