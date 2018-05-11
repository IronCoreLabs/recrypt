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

import CoreApi.{ reencryptionKeyTransform, transformKeyTransform, privateKeyTransform }
import cats.syntax.either._
import syntax.hashable._
final case class TransformKey(
  ephemeralPublicKey: PublicKey, //The ephemeral public key who encrypted the value
  toPublicKey: PublicKey, //The person or device that can decrypt the result
  encryptedTempKey: EncryptedElement, //The encrypted temp key value, which is used to go from the reencrypted value to the encrypted value
  hashedTempKey: HashedValue,
  publicSigningKey: PublicSigningKey,
  signature: Signature
) {

  /**
   * Augment the TransformKey. This should be done if the key that it's coming *from* was augmented.
   */
  def augment(privateKey: PrivateKey): Either[ApiError, TransformKey] = for {
    internalSignedKey <- transformKeyTransform(this).leftMap(InvalidTransformKey(_))
    //Note that this doesn't screw up the signing because augmentation tweaks the hashedK, which is not part of the
    //bytes that are used for the signature.
    newSignedValue = internalSignedKey.copy(payload = internalSignedKey.payload.augment(privateKeyTransform(privateKey), TransformKey.g1))
    result <- reencryptionKeyTransform(newSignedValue).leftMap(InvalidTransformKey(_))
  } yield result
}

object TransformKey {
  implicit val hashable: Hashable[TransformKey] = Hashable.by { tk: TransformKey =>
    tk.ephemeralPublicKey.toHashBytes ++ tk.toPublicKey.toHashBytes ++ tk.encryptedTempKey.toHashBytes ++
      tk.hashedTempKey.toHashBytes ++ tk.publicSigningKey.toHashBytes
  }
  private def g1: internal.point.HomogeneousPoint[internal.FP2Elem[internal.Fp]] = internal.Fp.curvePoints.g1
}
