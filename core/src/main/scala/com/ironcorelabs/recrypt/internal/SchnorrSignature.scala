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
import spire.implicits._
import cats.Eq

//  Both r and s will be positive values less than the order that was used to produce it.
//  r will be greater than zero.
final case class SchnorrSignature(r: BigInt, s: BigInt)

class SchnorrSigning[B <: BigInt: Eq: Hashable: Field](generator: point.HomogeneousPoint[B], order: BigInt)(implicit mods: ModsByPrime[B]) {
  val publicKeyGen = PublicKeyGen(generator)
  /**
   * Sign a message using our PRE privateKey. Also requires the corresponding (augmented) public key, which is
   * included in the hash in order to prevent forgery attacks.
   *
   * @param privateKey user's private PRE key
   * @param publicKey corresponding (augmented) public key
   * @param message the byte vector to sign
   * @param k random value between 1 and Curve.Order
   * @param sha256 hash function to apply to message with concatenated information
   * @return Option[SchnorrSignature] Some((r, s)) if successful, None if (Curve.g * k) is the zero point
   *   or if its x value mod Curve.Order was 0
   */
  def sign[A: Hashable](
    privateKey: PrivateKey[B],
    publicKey: PublicKey[B],
    message: A,
    k: BigInt,
    sha256: Sha256Hash
  ): Option[SchnorrSignature] = {
    if (k >= order) {
      // If g * k == the zero point, return None. This will only happen if (k mod Curve.Order) == 0
      // Also reject any values for k that are larger than Curve.Order. Though they would wrap around,
      // this potentially introduces a bias in the signatures. Since the caller should already need
      // to handle a return of None, just do that for any k >= Curve.Order, and let the caller retry.
      None
    } else {
      generator.times(k).normalize.flatMap {
        case (px, _) => {
          val r = positiveMod(px, order)
          if (r == BigIntZero)
            // Also need caller to try agian if we end up with a non-zero point that happens to have (x mod Curve.Order) == 0
            None
          else {
            //Create a value that's bigger than the Fp or Fp480 so either one will have a sufficiently large h
            val h = mods.create(sha256((r, publicKey, message)) ++ sha256((publicKey, message, r)))
            val s = positiveMod(k - h * privateKey.fp, order)
            Some(SchnorrSignature(r, s))
          }
        }
      }
    }
  }

  /**
   * Verify that signature of the message is valid using public key. This is complicated by the fact that the public
   * key that was supplied to the sign method was an augmented key, and to validate the signature, we need the pre-
   * augmentation public key that actually matches the private key. But we also need the augmented public key, because
   * we included it in the hash that we used for the signature. The caller should pass in the augmented public key and
   * the server's private augmenting key, and we will unravel everything.
   *
   * @param publicKey user's augmented public key
   * @param augmentingPrivateKey server's private key that was used to augment user's public key
   * @param message byte vector whose signature is being validated
   * @param signature signature that was generated for the message using user's private key
   * @param sha256 hash function to apply to message with concatenated information
   * @return Boolean true if signature is valid for message and specified keys, false otherwise
   */
  def verify[A: Hashable](
    publicKey: PublicKey[B],
    augmentingPrivateKey: PrivateKey[B],
    message: A,
    signature: SchnorrSignature,
    sha256: Sha256Hash
  ): Boolean = {
    val h = mods.create(sha256((signature.r, publicKey, message)) ++ sha256((publicKey, message, signature.r)))
    val augmentingPublicKey = publicKeyGen(augmentingPrivateKey)
    val unaugmentedKey = publicKey.value - augmentingPublicKey.value
    val v = generator.times(signature.s) + unaugmentedKey.times(h)
    v.normalize.fold(false) { case (x, _) => x == signature.r }
  }
}
