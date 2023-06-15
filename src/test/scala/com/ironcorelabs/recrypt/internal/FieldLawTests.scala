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
import org.typelevel.discipline.Predicate
import org.scalacheck.Arbitrary
import spire.laws.RingLaws
import Fp.implicits._
import Fp480.implicits._
import org.typelevel.discipline.scalatest.FunSuiteDiscipline
import org.scalatest.funsuite.AnyFunSuite

class FieldLawTests extends AnyFunSuite with org.scalatest.prop.Configuration with FunSuiteDiscipline {
  import Arbitraries._
  //Additive laws permit all elements.
  implicit def pred[A]: Predicate[A] = Predicate.const(true)
  implicit def fp6Arb: Arbitrary[FP6Elem[Fp]] = Arbitrary(fp6Gen[Fp])
  implicit val fp480Arb: Arbitrary[Fp480] = Arbitrary(nonZeroFp480Gen)
  implicit val fpArb: Arbitrary[Fp] = Arbitrary(nonZeroFpGen)

  implicit def fp6Arb480: Arbitrary[FP6Elem[Fp480]] = Arbitrary(fp6Gen[Fp480])
  checkAll("Fp256", RingLaws[Fp].field)
  checkAll("FP2Elem256", RingLaws[FP2Elem[Fp]].field)
  checkAll("FP6Elem256", RingLaws[FP6Elem[Fp]].field)
  checkAll("FP12Elem256", RingLaws[FP12Elem[Fp]].field)
  checkAll("HomogeneousPoint256", RingLaws[HomogeneousPoint[Fp]].additiveGroup)
  //Tests on the field instance for Fp480
  checkAll("Fp480", RingLaws[Fp480].field)
  checkAll("FP2Elem480", RingLaws[FP2Elem[Fp480]].field)
  checkAll("FP6Elem480", RingLaws[FP6Elem[Fp480]].field)
  checkAll("FP12Elem480", RingLaws[FP12Elem[Fp480]].field)
  checkAll("HomogeneousPoint480", RingLaws[HomogeneousPoint[Fp480]].additiveGroup)
  checkAll("HomogeneousPointFP2Elem480", RingLaws[HomogeneousPoint[FP2Elem[Fp480]]].additiveGroup)
}
