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

package recryptjs

import cats.effect.IO
import cats.data.NonEmptyVector
import scala.scalajs.js
import js.typedarray._

import js.annotation.{ JSExportAll, JSExportTopLevel }
import com.ironcorelabs.recrypt
import com.ironcorelabs.recrypt.EitherSyntax
import com.ironcorelabs.recrypt.syntax.hashable._
import scodec.bits.ByteVector
import js.JSConverters._
import cats.syntax.either._
import cats.syntax.traverse._

/**
 * This creates an instance of the public API for use from JS. This is a mirror of com.ironcorelabs.recrypt.Api, but with JS specific
 * datatypes so it can be called directly from JS.
 * randomBytes - An IO which will produce a cryptographically random array of bytes each time it's called.
 * sha256Func - An implementation of sha256. Note that the output should always be 32 bytes.
 * ed25519SignFunc - An implementation of the Ed25519 signing function.
 * ed25519VerifyFunc - An implementation of the Ed25519 verification function.
 */
@JSExportAll
@JSExportTopLevel("Api")
class Api(randomBytes: IO[ArrayBuffer], sha256Func: js.Function1[Uint8Array, Uint8Array],
  ed25519SignFunc: js.Function2[PrivateSigningKey, Uint8Array, Signature],
  ed25519VerifyFunc: js.Function3[PublicSigningKey, Uint8Array, Signature, Boolean]) {
  import Api._
  private val randomByteVector = randomBytes.map(b => ByteVector.view(TypedArrayBuffer.wrap(b)))
  private val scalaSha256Func = { byteVector: ByteVector => sha256Func(byteVector.toJSArray).toByteVector }
  private val scalaApi = new com.ironcorelabs.recrypt.CoreApi(randomByteVector, scalaSha256Func,
    recrypt.Ed25519Signing(
      (privateKey, message) => transformSignature(ed25519SignFunc(transformPrivateSigningKey(privateKey), message.toJSArray)),
      (key, message, signature) => ed25519VerifyFunc(transformPublicSigningKey(key), message.toJSArray, transformSignature(signature))
    ))

  /**
   * @see com.ironcorelabs.recrypt.Api.generateKeyPair
   */
  def generateKeyPair: IO[Keys] = scalaApi.generateKeyPair.map {
    case (privateKey, publicKey) => new Keys(transformPrivateKey(privateKey), transformPublicKey(publicKey))
  }

  /**
   * @see com.ironcorelabs.recrypt.Api.computePublicKey
   */
  def computePublicKey(privateKey: PrivateKey): IO[PublicKey] =
    scalaApi.computePublicKey(transformPrivateKey(privateKey)).map(transformPublicKey)

  /**
   * @see com.ironcorelabs.recrypt.Api.generatePlaintext
   */
  def generatePlaintext: IO[Plaintext] = scalaApi.generatePlaintext.map(transformPlaintext)

  /**
   * @see com.ironcorelabs.recrypt.Api.generateTransformKeys
   */
  def generateTransformKey(
    fromPrivateKey: PrivateKey,
    toPublicKey: PublicKey,
    fromPublicSigningKey: PublicSigningKey,
    fromPrivateSigningKey: PrivateSigningKey
  ): IO[TransformKey] =
    transformPublicKey(toPublicKey).flatMap(scalaApi.generateTransformKey(
      transformPrivateKey(fromPrivateKey),
      _,
      transformPublicSigningKey(fromPublicSigningKey),
      transformPrivateSigningKey(fromPrivateSigningKey)
    )).map(transformTransformKey)

  /**
   * @see com.ironcorelabs.recrypt.Api.encrypt
   */
  def encrypt(
    plaintext: Plaintext,
    toPublicKey: PublicKey,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): IO[EncryptedValue] =
    transformPublicKey(toPublicKey).flatMap(scalaApi.encrypt(
      transformPlaintext(plaintext),
      _,
      transformPublicSigningKey(publicSigningKey),
      transformPrivateSigningKey(privateSigningKey)
    )).map(transformEncryptedValue)

  /**
   * @see com.ironcorelabs.recrypt.Api.decrypt
   */
  def decrypt(encryptedValue: EncryptedValue, privateKey: PrivateKey): IO[Plaintext] =
    transformEncryptedValue(encryptedValue).flatMap(scalaApi.decrypt(_, transformPrivateKey(privateKey)).map(transformPlaintext).toIO)

  /**
   * @see com.ironcorelabs.recrypt.Api.transform
   */
  def transform(
    encryptedValue: EncryptedValue,
    transformKey: TransformKey,
    publicSigningKey: PublicSigningKey,
    privateSigningKey: PrivateSigningKey
  ): IO[EncryptedValue] = for {
    validEncryptedValue <- transformEncryptedValue(encryptedValue)
    validTransformKey <- transformTransformKey(transformKey)
    scalaResult <- scalaApi.transform(
      validEncryptedValue,
      validTransformKey,
      transformPublicSigningKey(publicSigningKey),
      transformPrivateSigningKey(privateSigningKey)
    )
  } yield transformEncryptedValue(scalaResult)

  /**
   * @see com.ironcorelabs.recrypt.Api.deriveSymmetricKey
   */
  def deriveSymmetricKey(plaintext: Plaintext): DecryptedSymmetricKey =
    transformDecryptedSymmetricKey(scalaApi.deriveSymmetricKey(transformPlaintext(plaintext)))

  /**
   * @see com.ironcorelabs.recrypt.Api.derivePrivateKey
   */
  def derivePrivateKey(plaintext: Plaintext): PrivateKey =
    transformPrivateKey(scalaApi.derivePrivateKey(transformPlaintext(plaintext)))

  /**
   * @see com.ironcorelabs.recrypt.Api.createTransformKeyBytes
   */
  def createTransformKeyBytes(transformKey: TransformKey): IO[TransformKeyBytes] =
    transformTransformKey(transformKey).map(_.toHashBytes).map(transformTransformKeyBytes)

  /**
   * @see com.ironcorelabs.recrypt.Api.schnorrSign
   */
  def schnorrSign(
    privateKey: PrivateKey,
    publicKey: PublicKey,
    message: SchnorrMessage
  ): IO[SchnorrSignature] =
    transformPublicKey(publicKey).flatMap(scalaApi.schnorrSign(
      transformPrivateKey(privateKey),
      _,
      transformSchnorrMessage(message)
    )).map(transformSchnorrSignature)

  // No schnorrVerify exposed - it requires a server public key, which will never be available in JS
}

object Api {
  @JSExportTopLevel("ioToFunc")
  def ioToFunc[A](io: IO[A], reject: js.Function1[js.Error, Unit], resolve: js.Function1[A, Unit]): Unit = io.unsafeRunAsync({
    case Left(t) => reject(new js.Error(t.getMessage))
    case Right(a) => resolve(a)
  })

  @JSExportTopLevel("callbackToIO")
  def callbackToIO[A](cb: js.Function2[js.Function1[A, Unit], js.Function1[js.Error, Unit], Unit]): IO[A] =
    //IO.async produces a value once, so we need to suspend that to keep producing new A's.
    IO.suspend(IO.async {
      cb.tupled.compose { in: (Either[Throwable, A] => Unit) =>
        ((a: A) => in(Right(a)), (e: js.Error) => in(Left(new Exception(e.message))))
      }
    })

  //Transform functions to/from all of types in recrypt's core to the JS exposed types that are exported above.
  //Note that in most cases there are 2 methods with the same name, this is because the names here often reflect the names in the
  //recrypt core.
  private def transformPrivateKey(p: PrivateKey) = recrypt.PrivateKey(p.bytes.toByteVector)
  private def transformPrivateKey(p: recrypt.PrivateKey) = new PrivateKey(p.bytes.toJSArray)

  private def transformPublicKey(p: PublicKey) = recrypt.PublicKey(p.x.toByteVector, p.y.toByteVector).leftMap(_.toString).toIO
  private def transformPublicKey(p: recrypt.PublicKey) = new PublicKey(p.x.toJSArray, p.y.toJSArray)

  private def transformPlaintext(a: Plaintext) = recrypt.Plaintext(a.bytes.toByteVector)
  private def transformPlaintext(a: recrypt.Plaintext) = new Plaintext(a.bytes.toJSArray)

  // private def transformDecryptedSymmetricKey(a: DecryptedSymmetricKey) = recrypt.DecryptedSymmetricKey(a.bytes.toByteVector)
  private def transformDecryptedSymmetricKey(a: recrypt.DecryptedSymmetricKey) = new DecryptedSymmetricKey(a.bytes.toJSArray)

  private def transformEncryptedMessage(a: EncryptedMessage) = recrypt.EncryptedMessage(a.bytes.toByteVector)
  private def transformEncryptedMessage(a: recrypt.EncryptedMessage) = new EncryptedMessage(a.bytes.toJSArray)

  private def transformAuthHash(a: AuthHash) = recrypt.AuthHash(a.bytes.toByteVector)
  private def transformAuthHash(a: recrypt.AuthHash) = new AuthHash(a.bytes.toJSArray)

  private def transformSignature(a: Signature) = recrypt.Signature(a.bytes.toByteVector)
  private def transformSignature(a: recrypt.Signature) = new Signature(a.bytes.toJSArray)

  private def transformPublicSigningKey(a: PublicSigningKey) = recrypt.PublicSigningKey(a.bytes.toByteVector)
  private def transformPublicSigningKey(a: recrypt.PublicSigningKey) = new PublicSigningKey(a.bytes.toJSArray)

  private def transformPrivateSigningKey(a: PrivateSigningKey) = recrypt.PrivateSigningKey(a.bytes.toByteVector)
  private def transformPrivateSigningKey(a: recrypt.PrivateSigningKey) = new PrivateSigningKey(a.bytes.toJSArray)

  private def transformHashedValue(a: HashedValue) = recrypt.HashedValue(a.bytes.toByteVector).leftMap(_.toString).toIO
  private def transformHashedValue(a: recrypt.HashedValue) = new HashedValue(a.bytes.toJSArray)

  private def transformEncryptedTempKey(a: EncryptedTempKey) = recrypt.EncryptedElement(a.bytes.toByteVector)
  private def transformEncryptedTempKey(a: recrypt.EncryptedElement) = new EncryptedTempKey(a.bytes.toJSArray)

  private def transformEncryptedValue(a: EncryptedValue) = a.transformBlocks.toList match {
    case Nil => transformPublicKey(a.ephemeralPublicKey).map(recrypt.EncryptedOnceValue(
      _,
      transformEncryptedMessage(a.encryptedMessage),
      transformAuthHash(a.authHash),
      transformPublicSigningKey(a.publicSigningKey),
      transformSignature(a.signature)
    ))
    case hd :: tail =>
      for {
        ephemeralPublicKey <- transformPublicKey(a.ephemeralPublicKey)
        transformBlocks <- NonEmptyVector.of(hd, tail: _*).traverse(transformTransformBlock)
      } yield recrypt.TransformedValue(
        ephemeralPublicKey,
        transformEncryptedMessage(a.encryptedMessage),
        transformAuthHash(a.authHash),
        transformBlocks,
        transformPublicSigningKey(a.publicSigningKey),
        transformSignature(a.signature)
      )
  }
  private def transformEncryptedValue(a: recrypt.EncryptedValue) = {
    val transformBlocks = a match {
      case t: recrypt.TransformedValue => t.transformBlocks.map(transformTransformBlock).toVector.toJSArray
      case _ => List[TransformBlock]().toJSArray
    }
    new EncryptedValue(
      transformPublicKey(a.ephemeralPublicKey),
      transformEncryptedMessage(a.encryptedMessage),
      transformAuthHash(a.authHash),
      transformBlocks,
      transformPublicSigningKey(a.publicSigningKey),
      transformSignature(a.signature)
    )
  }

  private def transformTransformBlock(a: TransformBlock) = for {
    publicKey <- transformPublicKey(a.publicKey)
    randomTransformPublicKey <- transformPublicKey(a.randomTransformPublicKey)
  } yield recrypt.TransformBlock(
    publicKey,
    transformEncryptedTempKey(a.encryptedTempKey),
    randomTransformPublicKey,
    transformEncryptedTempKey(a.randomTransformEncryptedTempKey)
  )
  private def transformTransformBlock(a: recrypt.TransformBlock) = new TransformBlock(
    transformPublicKey(a.publicKey),
    transformEncryptedTempKey(a.encryptedTempKey),
    transformPublicKey(a.randomTransformPublicKey),
    transformEncryptedTempKey(a.randomTransformEncryptedTempKey)
  )

  private def transformTransformKey(a: TransformKey) = for {
    ephemeralPublicKey <- transformPublicKey(a.ephemeralPublicKey)
    toPublicKey <- transformPublicKey(a.toPublicKey)
    hashedTempKey <- transformHashedValue(a.hashedTempKey)
  } yield recrypt.TransformKey(
    ephemeralPublicKey,
    toPublicKey,
    transformEncryptedTempKey(a.encryptedTempKey),
    hashedTempKey,
    transformPublicSigningKey(a.publicSigningKey),
    transformSignature(a.signature)
  )
  private def transformTransformKey(a: recrypt.TransformKey) = new TransformKey(
    transformPublicKey(a.ephemeralPublicKey),
    transformPublicKey(a.toPublicKey),
    transformEncryptedTempKey(a.encryptedTempKey),
    transformHashedValue(a.hashedTempKey),
    transformPublicSigningKey(a.publicSigningKey),
    transformSignature(a.signature)
  )

  // These are only one direction - the other direction isn't needed at this time
  private def transformTransformKeyBytes(a: ByteVector) = new TransformKeyBytes(a.toJSArray)
  private def transformSchnorrSignature(a: recrypt.SchnorrSignature) = new SchnorrSignature(a.bytes.toJSArray)
  private def transformSchnorrMessage(a: SchnorrMessage) = recrypt.SchnorrMessage(a.bytes.toByteVector)
}
