/**
 * This file is lifted from ironcore-id. We should publish it on github and share the dependency.
 */
package bench

import org.bouncycastle.crypto.params.{ Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters }
import org.bouncycastle.crypto.signers.Ed25519Signer
import scodec.bits.ByteVector

/**
 * Functions and types for working with the ed25519 signature.
 */
object Ed25519 { //scalastyle:ignore
  /**
   * An Ed25519 Public Key, which always has the correct length, can be used in `verify`
   */
  sealed abstract case class PublicKey(bytes: ByteVector) {
    override def toString: String = s"Ed25519.PublicKey as Base64: '${bytes.toBase64}'"
  }
  final object PublicKey {
    final val Length = 32
    final val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): PublicKey = new PublicKey(bytes) {}

    def unsafeFromBytes(b: ByteVector): PublicKey =
      fromBytes(b).getOrElse(throw new Exception(s"'$b' did not have $Length length."))

    def fromBytes(bytes: ByteVector): Option[PublicKey] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /**
     * Create a value by truncating-or-left-padding to the required length. This isn't ideal, but
     * because of the interaction with recrypt and lack of sizing guarantees (a la refined) it's needed.
     */
    def fromPaddedBytes(bytes: ByteVector): PublicKey =
      create(bytes
        .take(Length)
        .padLeft(Length))
  }

  /**
   * An Ed25519 Private Key, which always has the correct length, can be used in `verify`.
   *
   * WARNING: bytes are interpreted in the NaCl layout `seed (32) || publicKey (32)`. The
   * BouncyCastle backend only consumes the first 32 bytes (the seed); the trailing 32 bytes
   * are carried for byte-compat with the prior kalium implementation and the recrypt
   * `PrivateSigningKey` round-trip. If you construct a `PrivateKey` from bytes that do NOT
   * follow this layout, `sign` will produce signatures from whatever 32-byte prefix is present
   * and `verify` against the corresponding `PublicKey` will silently fail. Prefer
   * `generateKeyPair` to obtain a well-formed key.
   */
  sealed abstract case class PrivateKey(bytes: ByteVector) {
    //A protection against logging Private keys.
    override def toString: String = s"Ed25519.PrivateKey(<BYTES>)"

    /** The 32-byte Ed25519 seed (first half of the NaCl layout). */
    def seed: ByteVector = bytes.take(PrivateKey.SeedLength.toLong)

    /** The 32-byte public key embedded in this private key (second half of the NaCl layout). */
    def embeddedPublicKey: ByteVector = bytes.drop(PrivateKey.SeedLength.toLong)
  }
  final object PrivateKey {
    /** Length of the Ed25519 seed in bytes. */
    final val SeedLength = 32
    /** Total length of a NaCl-style Ed25519 private key: seed (32) || public key (32). */
    final val Length = SeedLength + PublicKey.Length
    final val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): PrivateKey = new PrivateKey(bytes) {}

    def fromBytes(bytes: ByteVector): Option[PrivateKey] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /**
     * Create a value by truncating-or-left-padding to the required length. This isn't ideal, but
     * because of the interaction with recrypt and lack of sizing guarantees (a la refined) it's needed.
     */
    def fromPaddedBytes(bytes: ByteVector): PrivateKey =
      create(bytes.take(LengthLong).padLeft(LengthLong))
  }

  /**
   * An Ed25519 signature, which always has the correct length, can be checked via `verify`
   */
  sealed abstract case class Signature(bytes: ByteVector) {
    override def toString: String = s"Signature in Base64: '${bytes.toBase64}'"
  }
  final object Signature {
    val Length = 64
    val LengthLong = Length.toLong
    private[Ed25519] def create(bytes: ByteVector): Signature = new Signature(bytes) {}

    def unsafeFromBytes(b: ByteVector): Signature =
      fromBytes(b).getOrElse(throw new Exception(s"'$b' did not have $Length length."))

    def fromBytes(bytes: ByteVector): Option[Signature] = Some(bytes)
      .filter(_.length == Length)
      .map(create)

    /**
     * Create a value by truncating-or-left-padding to the required length. This isn't ideal, but
     * because of the interaction with recrypt and lack of sizing guarantees (a la refined) it's needed.
     */
    def fromPaddedBytes(bytes: ByteVector): Signature =
      create(bytes
        .take(LengthLong)
        .padLeft(LengthLong))
  }

  def verify(key: PublicKey, message: ByteVector, signature: Signature): Boolean = {
    val verifier = new Ed25519Signer()
    val pubKeyParams = new Ed25519PublicKeyParameters(key.bytes.toArray, 0)
    verifier.init(false, pubKeyParams)
    val msgBytes = message.toArray
    verifier.update(msgBytes, 0, msgBytes.length)
    verifier.verifySignature(signature.bytes.toArray)
  }

  def sign(key: PrivateKey, message: ByteVector): Signature = {
    // BouncyCastle's Ed25519 takes only the 32-byte seed. We pull it from the NaCl-layout
    // private key via `key.seed`; see the WARNING on `PrivateKey` for what happens if the
    // caller built one from non-NaCl-format bytes.
    val signer = new Ed25519Signer()
    val privKeyParams = new Ed25519PrivateKeyParameters(key.seed.toArray, 0)
    signer.init(true, privKeyParams)
    val msgBytes = message.toArray
    signer.update(msgBytes, 0, msgBytes.length)
    Signature.create(ByteVector.view(signer.generateSignature()))
  }

  def generateKeyPair(seed: ByteVector): (PublicKey, PrivateKey) = {
    val privKeyParams = new Ed25519PrivateKeyParameters(seed.toArray, 0)
    val pubKeyParams = privKeyParams.generatePublicKey()
    val publicKeyBytes = ByteVector.view(pubKeyParams.getEncoded)
    // Reconstruct the NaCl-style 64-byte private key: seed || public key.
    val privateKeyBytes = seed ++ publicKeyBytes
    PublicKey.create(publicKeyBytes) -> PrivateKey.create(privateKeyBytes)
  }
}
