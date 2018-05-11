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
import cats.data.NonEmptyVector
import scodec.bits._
import com.ironcorelabs.recrypt.syntax.hashable._
import Fp.implicits._

class EncryptedValueTest extends com.ironcorelabs.recrypt.TestBase {
  val keyGen = Fp.curvePoints.publicKeyGen
  val privateKey = PrivateKey(Fp(BigInt("-22")))
  val pairing = new Pairing[Fp]()
  val plaintext = pairing.finalExponentiation(FP12Elem.create(Fp(-11), Fp(3), Fp(3), Fp(-4), Fp(5), Fp(6), Fp(6), Fp(32), Fp(-1), Fp(32), Fp(4), Fp(1)))
  val publicKey = keyGen(privateKey)

  "EncryptedOnceValue authHash is included in toHashBytes" in {
    val eov1: EncryptedValue[Fp] = EncryptedOnceValue(publicKey, plaintext, AuthHash(hex"00ff00ff"))
    val hash1 = eov1.toHashBytes
    val eov2: EncryptedValue[Fp] = EncryptedOnceValue(publicKey, plaintext, AuthHash(hex"00ff00f3"))
    val hash2 = eov2.toHashBytes

    hash1 shouldNot be(hash2)
  }

  "ReencryptedValue authHash is included in toHashBytes" in {
    val eov1: EncryptedValue[Fp] = ReencryptedValue(publicKey, plaintext, AuthHash(hex"00ff00ff"), NonEmptyVector(ReencryptionBlock(publicKey, plaintext, publicKey, plaintext), Vector()))
    val hash1 = eov1.toHashBytes
    val eov2: EncryptedValue[Fp] = ReencryptedValue(publicKey, plaintext, AuthHash(hex"00ff00fe"), NonEmptyVector(ReencryptionBlock(publicKey, plaintext, publicKey, plaintext), Vector()))
    val hash2 = eov2.toHashBytes

    hash1 shouldNot be(hash2)
  }
}
