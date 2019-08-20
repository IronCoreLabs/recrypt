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
import point.HomogeneousPoint
import scodec.bits.ByteVector
import cats.Eq
import cats.syntax.either._
import cats.syntax.contravariant._
import spire.implicits._

/**
 * In our PRE scheme, a private key is simply a BigInt value in Fp - that is, an integer in
 * [0, Prime - 1]. The public key is just the generator point in E(Fp) times the private
 * key value. Since E(Fp) is a cyclic group, multiplying a point by any value that is larger
 * than Curve.Order will actually "wrap around" and be equivalent to multiplying by the
 * value mod Curve.Order.
 */
final case class PublicKeyGen[FpType <: BigInt](generator: HomogeneousPoint[FpType]) extends AnyVal {
  def apply(privateKey: PrivateKey[FpType]): PublicKey[FpType] = PublicKey(generator.times(privateKey.toBigInt))
}

//Maybe this should be arbitrary bytes, but it should be functionally identical.
final case class PrivateKey[FpType <: BigInt](fp: FpType) extends AnyVal {
  override def toString: String = "<PRIVATE KEY>"
  def toBigInt: BigInt = fp
  def +(that: PrivateKey[FpType])(implicit mods: ModsByPrime[FpType]) = PrivateKey(mods.create(this.fp + that.fp))
}

object PrivateKey {
  def fromBigInt(b: BigInt): PrivateKey[Fp] = PrivateKey(Fp(b))
  def fromByteVector[A <: BigInt](b: ByteVector)(implicit mods: ModsByPrime[A]): PrivateKey[A] = PrivateKey(mods.create(b))
}

/**
 * Constructor hidden because `PublicKeyGen` should be used to produce these
 */
final case class PublicKey[FpType] private[internal] (value: HomogeneousPoint[FpType]) extends AnyVal {
  def toByteVectors(implicit hashableFpType: Hashable[FpType]): Option[(ByteVector, ByteVector)] =
    value.normalize.map { case (x, y) => hashableFpType(x) -> hashableFpType(y) }

  /**
   * Augment this public key to be the sum of this plus the other.
   */
  def augment(other: PublicKey[FpType])(implicit fieldFpType: Field[FpType], eqFpType: cats.Eq[FpType]): PublicKey[FpType] =
    PublicKey[FpType](value + other.value)
}

object PublicKey {
  def fromByteVectors[A: Field: Eq](x: ByteVector, y: ByteVector)(implicit bytesDecoder: BytesDecoder[A]): Either[PointError, PublicKey[A]] = for {
    ax <- bytesDecoder.decode(x).leftMap(decodeError => InvalidCoordinate(x, decodeError.toString))
    ay <- bytesDecoder.decode(y).leftMap(decodeError => InvalidCoordinate(x, decodeError.toString))
    point <- HomogeneousPoint(ax, ay)
  } yield new PublicKey(point)
  implicit def hashable[A: Hashable]: Hashable[PublicKey[A]] = Hashable[Option[(A, A)]].contramap { _.value.normalize }
  implicit def eq[A: Eq]: Eq[PublicKey[A]] = Eq.by { _.value.normalize }
}

/**
 * A reencryption key allows a message encrypted to one public key (the key of the delegator)
 * to be transformed as if it was encrypted to another public key (the key of hte delegatee),
 * so it can be decrypted using the delegatee's private key.
 */
final case class ReencryptionKey[FpType <: BigInt](
  rePublicKey: PublicKey[FpType], //An ephemeral key that is randomly chosen when this reencryption key is generated
  toPublicKey: PublicKey[FpType], //The person or device that can decrypt the result
  encryptedK: FP12Elem[FpType], //A random value in G_T, encrypted to the toPublicKey
  hashedK: HomogeneousPoint[FP2Elem[FpType]] // A hashed version of the random value from G_T, used to perform the transform
) {
  /**
   * Augment the transform key. It's augmented using the inverse of the augmentation key to "undo"
   * the augmentation we did in the public key that created this key.
   */
  def augment(privateKey: PrivateKey[FpType], g1: HomogeneousPoint[FP2Elem[FpType]]): ReencryptionKey[FpType] =
    copy(hashedK = g1.times(-privateKey.fp).add(hashedK))
}

object ReencryptionKey {
  implicit def hashable[A <: BigInt: Hashable]: Hashable[ReencryptionKey[A]] = Hashable[(PublicKey[A], PublicKey[A], FP12Elem[A])].contramap {
    //Note that the hashedK is not included in the hashable bytes.
    case ReencryptionKey(rePublicKey, toPublicKey, encryptedK, _) => (rePublicKey, toPublicKey, encryptedK)
  }
}
