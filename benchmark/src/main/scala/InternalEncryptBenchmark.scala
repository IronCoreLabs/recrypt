package bench

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._

import com.ironcorelabs.recrypt.internal._
import scodec.bits.ByteVector

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.SECONDS)
class InternalEncryptBenchmark extends BenchmarkHelper {
  import Fp.implicits._
  private val keyGen = Fp.curvePoints.publicKeyGen
  val encryptInstance = new InternalApi(
    Sha256Hash { bytes: ByteVector =>
      ByteVector.view(java.security.MessageDigest.getInstance("SHA-256").digest(bytes.toArray))
    },
    Ed25519Signing((_, _) => Signature.empty, (_, _, _) => true),
    Fp.curvePoints
  )
  private val privateKey = PrivateKey.fromBigInt(BigInt("17561965855055966875289582496526669116201409974621952158489640859240156546764"))

  private val publicSigningKey = PublicSigningKey(ByteVector.empty)
  private val privateSigningKey = PrivateSigningKey(ByteVector.empty)
  private val plaintext = encryptInstance.generateRthRoot(randomFp12IO.unsafeRunSync)
  private val publicKey = keyGen(privateKey)
  private val emphemPrivateKey = PrivateKey.fromBigInt(BigInt("7982134798234178911111"))
  private val encryptedData = encryptInstance.encrypt(publicKey, plaintext, emphemPrivateKey, publicSigningKey, privateSigningKey)
  private val salt1 = encryptInstance.generateRthRoot(randomFp12IO.unsafeRunSync)
  private val reencryptionPrivate = PrivateKey.fromBigInt(BigInt("22002131259228303741090495322318969764532178674829148099822698556219881568451"))
  private val raRePrivateKey = PrivateKey.fromBigInt(BigInt("17561965855055966875289582496525889116201409974621952158489640859240156546764"))
  private val raReK = encryptInstance.generateRthRoot(randomFp12IO.unsafeRunSync)
  private val reencryptionKey = encryptInstance.generateReencryptionKey(
    privateKey,
    publicKey,
    reencryptionPrivate,
    salt1,
    publicSigningKey,
    privateSigningKey
  )
  private val reencryptedValue = encryptInstance.reencrypt(reencryptionKey, encryptedData,
    raRePrivateKey, raReK, publicSigningKey, privateSigningKey).right.toOption.get

  @Benchmark
  def generatePublicKey = keyGen(privateKey)

  @Benchmark
  def pair = encryptInstance.pair(Fp.curvePoints.generator, Fp.curvePoints.g1)

  @Benchmark
  def encryptLevel1 = encryptInstance.encrypt(publicKey, plaintext, emphemPrivateKey, publicSigningKey, privateSigningKey)

  @Benchmark
  def reencryptToLevel2 = encryptInstance.reencrypt(reencryptionKey, encryptedData, raRePrivateKey, raReK, publicSigningKey, privateSigningKey)

  @Benchmark
  def reencryptionKeyGen = encryptInstance.generateReencryptionKey(
    privateKey,
    publicKey,
    reencryptionPrivate,
    salt1,
    PublicSigningKey(ByteVector.empty),
    PrivateSigningKey(ByteVector.empty)
  )

  @Benchmark
  def reencryptToLevel3 = encryptInstance.reencrypt(reencryptionKey, reencryptedValue, privateKey, salt1, publicSigningKey, privateSigningKey)

  @Benchmark
  def decryptLevel1 = encryptInstance.decrypt(privateKey, encryptedData)

  @Benchmark
  def decryptLevel2 = encryptInstance.decrypt(privateKey, reencryptedValue)
}
