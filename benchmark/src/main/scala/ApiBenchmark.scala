package bench

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._

import com.ironcorelabs.recrypt

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.SECONDS)
class ApiBenchmark extends BenchmarkHelper {
  final val Ed25519Instance = recrypt.Ed25519Signing(
    { (privateRecryptKey, message) =>
      val sig = Ed25519.sign(
        //To be safe, just pad out the bytes we get from recrypt.
        Ed25519.PrivateKey.fromPaddedBytes(privateRecryptKey.bytes),
        message
      )
      recrypt.Signature(sig.bytes)
    },
    { (publicRecryptKey, message, signature) =>
      Ed25519.verify(
        //To be safe, just pad out the bytes we get from recrypt.
        Ed25519.PublicKey.fromPaddedBytes(publicRecryptKey.bytes),
        message,
        Ed25519.Signature.fromPaddedBytes(signature.bytes)
      )
    }
  )
  val api = new recrypt.Api(randomBytesIO, Ed25519Instance)

  var publicKey: recrypt.PublicKey = _
  var privateKey: recrypt.PrivateKey = _
  var plaintext: recrypt.Plaintext = _
  var privateSigningKey: recrypt.PrivateSigningKey = _
  var publicSigningKey: recrypt.PublicSigningKey = _
  var encryptedMessage: recrypt.EncryptedValue = _
  var transformKey: recrypt.TransformKey = _

  @Setup
  def setup(): Unit = {
    val keyPair = api.generateKeyPair.unsafeRunSync()
    privateKey = keyPair._1
    publicKey = keyPair._2
    plaintext = api.generatePlaintext.unsafeRunSync()
    val signingKeyPair = randomBytesIO.map(Ed25519.generateKeyPair).unsafeRunSync()
    publicSigningKey = recrypt.PublicSigningKey(signingKeyPair._1.bytes)
    privateSigningKey = recrypt.PrivateSigningKey(signingKeyPair._2.bytes)
    encryptedMessage = api.encrypt(plaintext, publicKey, publicSigningKey, privateSigningKey).unsafeRunSync()
    transformKey = api.generateTransformKey(privateKey, publicKey, publicSigningKey, privateSigningKey).unsafeRunSync()
  }

  @Benchmark
  def encrypt() = api.encrypt(plaintext, publicKey, publicSigningKey, privateSigningKey).unsafeRunSync()

  @Benchmark
  def transform() = api.transform(encryptedMessage, transformKey, publicSigningKey, privateSigningKey).unsafeRunSync()

  @Benchmark
  def computePublicKey() = api.computePublicKey(privateKey).unsafeRunSync()
}
