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
import Fp.implicits._
import cats.Eq

class PublicKeyGenTest extends com.ironcorelabs.recrypt.TestBase {

  "KeyGen" should {
    "generate known key" in {
      val privateKey = PrivateKey.fromBigInt(BigInt("37777967648492203239675772600961898148040325589588086812374811831221462604944"))
      val expectedResult = PublicKey(HomogeneousPoint(Fp(BigInt("56377452267431283559088187378398270325210563762492926393848580098576649271541")), Fp(BigInt("46643694276241842996939080253335644316475473619096522181405937227991761798154"))).value)
      val result = new PublicKeyGen(Fp.curvePoints.generator)(privateKey)
      val eq = Eq[PublicKey[Fp]]
      eq.eqv(result, expectedResult) shouldBe true
    }

    "generate known key (max 32-byte private key)" in {
      val privateKey = PrivateKey.fromBigInt(BigInt("50791539541669591690774546266328002110444626558017560467580438981048945568152"))
      val expectedResult = PublicKey(HomogeneousPoint(Fp(BigInt("58483620629232886210555514960799664032881966270053836377116209031946678864174")), Fp(BigInt("39604663823550822619127054070927331080305575010367415285113646212320556073913"))).value)
      val result = PublicKeyGen(Fp.curvePoints.generator)(privateKey)
      val eq = Eq[PublicKey[Fp]]
      eq.eqv(result, expectedResult) shouldBe true
    }
  }
}
