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

package com.ironcorelabs.recrypt

import scodec.bits.ByteVector
import CoreApi.publicKeyTransform
import cats.syntax.either._
import internal.Fp.implicits._

/**
 * Public key which can be encrypted to. Ideally this would just be the internal
 * public key, but for now that is backed by AffinePoint, which means it's a pain.
 *
 * This is guarenteed to be a valid point on the curve by construction.
 */
sealed abstract case class PublicKey(x: ByteVector, y: ByteVector) {
  /**
   * Augment the public key with another PublicKey. The augmented public key will be the one that is used for any encryption.
   * Note that if a public key has been augmented, any TransformKeys that are created to delegate decryption from that key
   * to another key pair must be augmented using the private key which produced this public key.
   */
  def augment(otherPublicKey: PublicKey): Either[ApiError, PublicKey] = {
    import internal.Fp.implicits._
    publicKeyTransform(internalKey.augment(otherPublicKey.internalKey)).toRight[ApiError](InvalidPublicKey)
  }

  private[recrypt] def internalKey: internal.PublicKey[internal.Fp]
}

object PublicKey {
  implicit val hashable: Hashable[PublicKey] = Hashable.by { (pk: PublicKey) => pk.x ++ pk.y }

  def apply(x: ByteVector, y: ByteVector): Either[ApiError, PublicKey] =
    internal.PublicKey.fromByteVectors(x, y).leftMap(_ => InvalidPublicKey).map(internalPK => new PublicKey(x, y) { val internalKey = internalPK })

  /**
   * Private to the package so we don't expose the internal public key in the public methods.
   */
  private[recrypt] def fromInternal(p: internal.PublicKey[internal.Fp]): Option[PublicKey] = p.toByteVectors.map {
    case (publicX, publicY) => new PublicKey(publicX, publicY) { val internalKey = p }
  }
}
