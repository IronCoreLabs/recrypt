/** This file is lifted from ironcore-id. We should publish it on github and
  * share the dependency.
  */
package bench

import org.abstractj.kalium.NaCl.Sodium.{
  CRYPTO_SIGN_ED25519_PUBLICKEYBYTES,
  CRYPTO_SIGN_ED25519_BYTES,
  CRYPTO_SIGN_ED25519_SECRETKEYBYTES
} //scalastyle:ignore
import org.abstractj.kalium.NaCl.sodium
import scodec.bits.ByteVector
import jnr.ffi.byref.LongLongByReference

/** Functions and types for working with the ed25519 signature.
  */
object Ed25519 { // scalastyle:ignore
  /** An Ed25519 Public Key, which always has the correct length, can be used in
    * `verify`
    */
  sealed abstract case class PublicKey(bytes: ByteVector) {
    override def toString: String =
      s"Ed25519.PublicKey as Base64: '${bytes.toBase64}'"
  }
  object PublicKey {
    final val Length = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
    final val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): PublicKey = new PublicKey(
      bytes
    ) {}

    def unsafeFromBytes(b: ByteVector): PublicKey =
      fromBytes(b).getOrElse(
        throw new Exception(s"'$b' did not have $Length length.")
      )

    /** Verifies the length of the byte vector satisfies the invariant detailed
      * in NaCl
      */
    def fromBytes(bytes: ByteVector): Option[PublicKey] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /** Create a value safely by just taking and padding bytes. This isn't
      * ideal, but because of the interaction with recrypt and lack of sizing
      * guarentees (a la refined) it's needed.
      */
    def fromPaddedBytes(bytes: ByteVector): PublicKey =
      create(
        bytes
          .take(Length)
          .padLeft(Length)
      )
  }

  /** An Ed25519 Private Key, which always has the correct length, can be used
    * in `verify`
    */
  sealed abstract case class PrivateKey(bytes: ByteVector) {
    // A protection against logging Private keys.
    override def toString: String = s"Ed25519.PrivateKey(<BYTES>)"
  }
  object PrivateKey {
    final val Length = CRYPTO_SIGN_ED25519_SECRETKEYBYTES
    final val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): PrivateKey = new PrivateKey(
      bytes
    ) {}

    /** Verifies the length of the byte vector satisfies the invariant detailed
      * in NaCl.
      */
    def fromBytes(bytes: ByteVector): Option[PrivateKey] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /** Create a value safely by just taking and padding bytes. This isn't
      * ideal, but because of the interaction with recrypt and lack of sizing
      * guarentees (a la refined) it's needed.
      */
    def fromPaddedBytes(bytes: ByteVector): PrivateKey =
      create(bytes.take(LengthLong).padLeft(LengthLong))
  }

  /** An Ed25519 signature, which always has the correct length, can be checked
    * via `verify`
    */
  sealed abstract case class Signature(bytes: ByteVector) {
    override def toString: String = s"Signature in Base64: '${bytes.toBase64}'"
  }
  object Signature {
    val Length = CRYPTO_SIGN_ED25519_BYTES
    val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): Signature = new Signature(
      bytes
    ) {}

    def unsafeFromBytes(b: ByteVector): Signature =
      fromBytes(b).getOrElse(
        throw new Exception(s"'$b' did not have $Length length.")
      )

    /** Verifies the length of the byte vector satisfies the invariant detailed
      * in NaCl
      */
    def fromBytes(bytes: ByteVector): Option[Signature] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /** Create a value safely by just taking and padding bytes. This isn't
      * ideal, but because of the interaction with recrypt and lack of sizing
      * guarentees (a la refined) it's needed.
      */
    def fromPaddedBytes(bytes: ByteVector): Signature =
      create(
        bytes
          .take(LengthLong)
          .padLeft(LengthLong)
      )

  }

  def verify(
      key: PublicKey,
      message: ByteVector,
      signature: Signature
  ): Boolean = {
    val mergedBytes = signature.bytes ++ message
    val mergedByteArray = mergedBytes.toArray
    val sodiumResult = sodium.crypto_sign_ed25519_open(
      arrayOfZeros(
        mergedByteArray.length
      ), // Out buffer which we don't need the result of
      new LongLongByReference(
        0
      ), // Out buffer length which we don't need the result of
      mergedByteArray, // signature + message bytes
      mergedByteArray.length, // signature + message bytes length
      key.bytes.toArray // public key bytes
    )
    isValid(sodiumResult)
  }

  def sign(key: PrivateKey, message: ByteVector): Signature = {
    val messageLength = message.length.toInt
    val privateKeyBytes = key.bytes.toArray

    val outputByteArray = arrayOfZeros(messageLength + Signature.Length)
    sodium.crypto_sign_ed25519(
      outputByteArray,
      new LongLongByReference(0), // Don't care.
      message.toArray,
      messageLength,
      privateKeyBytes
    )
    Signature.create(
      ByteVector.view(outputByteArray).take(Signature.LengthLong)
    )
  }

  def generateKeyPair(seed: ByteVector): (PublicKey, PrivateKey) = {
    // Allocate the arrays, which will get filled out by crypto_sign_ed25519_seed_keypair
    val privateKeyArray = arrayOfZeros(PrivateKey.Length)
    val publicKeyArray = arrayOfZeros(PublicKey.Length)
    sodium.crypto_sign_ed25519_seed_keypair(
      publicKeyArray,
      privateKeyArray,
      seed.toArray
    )
    PublicKey.create(ByteVector.view(publicKeyArray)) -> PrivateKey.create(
      ByteVector.view(privateKeyArray)
    )
  }

  final private def isValid(code: Int): Boolean = code == 0

  final private def arrayOfZeros(n: Int): Array[Byte] = new Array[Byte](n)
}
