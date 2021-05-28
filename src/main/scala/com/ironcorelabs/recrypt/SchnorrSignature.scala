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

/**
 * Functions and types for working with the Schnorr signature. Similar to the Ed25519
 * signing, but we use our existing PRE public and private keys for Schnorr signing
 * and verification, so this type only includes the Signature.
 *
 * A Schnorr signature is actually two parts, r and s. Each of them will fit into a 32-byte ByteVector;
 * r will convert to a BigInt in the range [1 .. Curve.Order), and s will convert to a BigInt in the range
 * [0 .. Curve.Order).
 * But we keep that detail internal; externally, the signature is just a single 64-byte ByteVector.
 */
sealed abstract case class SchnorrSignature(bytes: ByteVector) {
  override def toString: String = s"Signature in Base64: '${bytes.toBase64}'"

  def toBigInts: (BigInt, BigInt) = {
    val (rBytes, sBytes) = bytes.splitAt(SchnorrSignature.rLengthLong)
    (internal.byteVectorToBigInt(rBytes), internal.byteVectorToBigInt(sBytes))
  }
}

final object SchnorrSignature {
  private val rLengthLong = 32L
  private val sLengthLong = 32L
  val LengthLong = rLengthLong + sLengthLong
  val Length = LengthLong.toInt

  private def create(bytes: ByteVector): SchnorrSignature = new SchnorrSignature(bytes) {}
  def unapply(s: String): Option[SchnorrSignature] = fromBase64(s)

  // Verifies that the length of the byte vector is correct
  def fromBytes(bytes: ByteVector): Option[SchnorrSignature] =
    Some(bytes).filter(_.length == LengthLong).map(create)

  // Throw caution (and exceptions) to the wind, if string didn't have correct length
  def unsafeFromBytes(bytes: ByteVector): SchnorrSignature =
    fromBytes(bytes).getOrElse(throw new Exception(s"'$bytes' did not have $Length length."))

  // Create a value safely by just taking and padding bytes. Maybe not ideal, but necessary without having
  // any size guarantees (a la refined).
  def fromPaddedBytes(bytes: ByteVector): SchnorrSignature =
    create(bytes.take(LengthLong).padLeft(LengthLong))

  def fromBase64(base64String: String): Option[SchnorrSignature] =
    ByteVector.fromBase64(base64String).flatMap(base64Bytes => fromBytes(base64Bytes))

  /**
   * The internal representation is a pair of BigInts, r and s. Provide a way to create the opaque ByteVector
   * from these values.
   */
  def fromBigInts(r: BigInt, s: BigInt): SchnorrSignature =
    create(internal.Fp.bigIntToByteVector(r).padLeft(rLengthLong) ++ internal.Fp.bigIntToByteVector(s).padLeft(sLengthLong))
}

final case class SchnorrMessage(bytes: ByteVector)
object SchnorrMessage {
  implicit val hashable: Hashable[SchnorrMessage] = Hashable.by(_.bytes)
}
