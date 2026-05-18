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

package bench

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import scodec.bits.ByteVector

class Ed25519Test extends AnyWordSpec with Matchers {
  // A fixed 32-byte seed so failures are reproducible.
  private val seed = ByteVector.fromValidHex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  )
  private val message = ByteVector.encodeUtf8("recrypt benchmark sanity check").toOption.get

  "Ed25519.generateKeyPair" should {
    "produce a 32-byte public key and a 64-byte NaCl-layout private key" in {
      val (pub, priv) = Ed25519.generateKeyPair(seed)
      pub.bytes.length shouldBe Ed25519.PublicKey.Length
      priv.bytes.length shouldBe Ed25519.PrivateKey.Length
    }

    "embed the public key as the second half of the private key" in {
      val (pub, priv) = Ed25519.generateKeyPair(seed)
      priv.seed shouldBe seed
      priv.embeddedPublicKey shouldBe pub.bytes
    }

    "be deterministic for a given seed" in {
      val a = Ed25519.generateKeyPair(seed)
      val b = Ed25519.generateKeyPair(seed)
      a._1.bytes shouldBe b._1.bytes
      a._2.bytes shouldBe b._2.bytes
    }
  }

  "Ed25519.sign / verify" should {
    "round-trip a signature produced from a freshly generated key" in {
      val (pub, priv) = Ed25519.generateKeyPair(seed)
      val sig = Ed25519.sign(priv, message)
      sig.bytes.length shouldBe Ed25519.Signature.Length
      Ed25519.verify(pub, message, sig) shouldBe true
    }

    "reject a signature whose bytes have been tampered with" in {
      val (pub, priv) = Ed25519.generateKeyPair(seed)
      val sig = Ed25519.sign(priv, message)
      val tampered = Ed25519.Signature.unsafeFromBytes(sig.bytes.update(0, (sig.bytes(0) ^ 0x01).toByte))
      Ed25519.verify(pub, message, tampered) shouldBe false
    }

    "reject a valid signature against a different message" in {
      val (pub, priv) = Ed25519.generateKeyPair(seed)
      val sig = Ed25519.sign(priv, message)
      val otherMessage = message ++ ByteVector(0x00.toByte)
      Ed25519.verify(pub, otherMessage, sig) shouldBe false
    }

    "reject a valid signature against an unrelated public key" in {
      val (_, priv) = Ed25519.generateKeyPair(seed)
      val otherSeed = ByteVector.fill(Ed25519.PrivateKey.SeedLength.toLong)(0x42.toByte)
      val (otherPub, _) = Ed25519.generateKeyPair(otherSeed)
      val sig = Ed25519.sign(priv, message)
      Ed25519.verify(otherPub, message, sig) shouldBe false
    }
  }
}
