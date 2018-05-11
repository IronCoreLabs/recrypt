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
import cats.effect.IO
import cats.instances.list._
import cats.syntax.traverse._
import com.ironcorelabs.recrypt.internal.Arbitraries._
import com.ironcorelabs.recrypt.syntax.hashable._
import com.ironcorelabs.recrypt.internal.point.HomogeneousPoint
import org.scalacheck.Arbitrary
import scodec.bits._
import spire.algebra.Field
import Fp.implicits._
import Fp480.implicits._

class InternalApiTest extends com.ironcorelabs.recrypt.TestBase {
  import InternalApiTest._
  val curvePoints = Fp.curvePoints
  val encryptInstance = createEncryptWithoutSigning(com.ironcorelabs.recrypt.Sha256)
  val basePoint = curvePoints.generator
  val (basePointX, basePointY) = basePoint.normalize.value
  val keyGen = PublicKeyGen(basePoint)
  val privateSigningKey = PrivateSigningKey.empty
  val publicSigningKey = PublicSigningKey.empty
  val sha256Hash = Sha256Hash(com.ironcorelabs.recrypt.Sha256)
  //All Fps in this file should be non-zero.
  implicit val fpArb = Arbitrary(nonZeroFpGen)
  implicit val fp480Arb = Arbitrary(nonZeroFp480Gen)

  private val randomBytesIO: IO[ByteVector] = {
    //Start with a known value, we'll just add one to it each time
    var i = 100L
    val hashFunc = java.security.MessageDigest.getInstance("SHA-256").digest(_: Array[Byte])
    IO {
      i += 1
      ByteVector.view(hashFunc(List(i.byteValue).toArray))
    }
  }

  private val randomFP12IO: IO[FP12Elem[Fp]] = {
    val randCoefList = List.fill(12)(randomBytesIO.map(Fp(_))).sequence
    randCoefList.map {
      case fp1 :: fp2 :: fp3 :: fp4 :: fp5 :: fp6 :: fp7 :: fp8 :: fp9 :: fp10 :: fp11 :: fp12 :: Nil =>
        FP12Elem.create(fp1, fp2, fp3, fp4, fp5, fp6, fp7, fp8, fp9, fp10, fp11, fp12)
      case _ => throw new Exception("Unless someone breaks the randCoefList above, this can't happen.")
    }
  }

  def genReencryptionKey(fromPrivate: PrivateKey[Fp], toPublicKey: PublicKey[Fp]) = for {
    reencryptionPrivate <- Arbitrary.arbitrary[PrivateKey[Fp]]
    salt <- Arbitrary.arbitrary[FP12Elem[Fp]]
  } yield encryptInstance.generateReencryptionKey(fromPrivate, toPublicKey, reencryptionPrivate, salt, PublicSigningKey.empty, PrivateSigningKey.empty)

  val goodHomogeneousPoint = HomogeneousPoint[FP2Elem[Fp]](
    FP2Elem(Fp(BigInt("39898887170429929807040143276261848585078991568615066857293752634765338134660")), Fp(BigInt("4145079839513126747718408015399244712098849008922890496895080944648891367549"))),
    FP2Elem(Fp(BigInt("54517427188233403272140512636254575372766895942651963572804557077716421872651")), Fp(BigInt("29928198841033477396304275898313889635561368630804063259494165651195801046334"))),
    FP2Elem(Fp(BigInt("25757029117904574834370194644693146689936696995375576562303493881177613755324")), Fp(BigInt("20317563273514500379895253969863230147776170908243485486513578790623697384796")))
  )

  "generateRthRoot" should {
    "generate output of 1 for input of 1" in {
      val fp12One = Field[FP12Elem[Fp]].one
      val result = encryptInstance.generateRthRoot(fp12One)
      result shouldBe fp12One
    }
    "match known value" in {
      val expectedGoodResult = FP12Elem.create(
        Fp(BigInt("49613603272845344677661086705817470185880010673415833593829669044018497549835")),
        Fp(BigInt("22166694560998028876421308244727009462749749876972607539162845336867310554274")),
        Fp(BigInt("27106324204537258291745241393453966242243529809976728689636328293851256130935")),
        Fp(BigInt("58881687045891995070474384773128780876513275718265760275916904929606114986406")),
        Fp(BigInt("45768403989745772521090577909263347508554672259686169121453713692090586113967")),
        Fp(BigInt("22343259069418190906039702358532734337019270494074315993998476890795563606527")),
        Fp(BigInt("10318321283537597124591332916540849109474607700311611005627842594481213916850")),
        Fp(BigInt("64931065515411805756507685624487790930781380721035645300571099874425376175085")),
        Fp(BigInt("52904934831519375356336252527424369066383607534870219573443362493419150342310")),
        Fp(BigInt("63487392288061763043701517644941780158532021261148714086587409819851975632119")),
        Fp(BigInt("8597312250525367683838914964059417598760950131137782095395959535602139476721")),
        Fp(BigInt("32639342264133288455975631146383164602670197489245655599945675104556059689674"))
      )
      val result = encryptInstance.generateRthRoot(
        FP12Elem.create(
          Fp(BigInt(1)), Fp(BigInt(2)), Fp(BigInt(3)), Fp(BigInt(4)), Fp(BigInt(5)), Fp(BigInt(6)),
          Fp(BigInt(7)), Fp(BigInt(8)), Fp(BigInt(9)), Fp(BigInt(10)), Fp(BigInt(11)), Fp(BigInt(12))
        )
      )
      result shouldBe expectedGoodResult
    }
    "always produce an rth root" in {
      forAll(Arbitrary.arbitrary[FP12Elem[Fp]]) { fp12 =>
        whenever(fp12 != Field[FP12Elem[Fp]].zero) {
          val rthRoot = encryptInstance.generateRthRoot(fp12)
          val rthPow = rthRoot ^ Fp.Order
          rthPow shouldBe Field[FP12Elem[Fp]].one
        }
      }
    }
  }

  "addLineEval" should {
    "match known value" in {
      val expectedGoodResult = FP12Elem.create(
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("10225613897589023975141864306784331698114333350322193013849355029116866989558")), Fp(BigInt("23874417408544625227955020078213054360178217578435813388951341839988775845640")),
        Fp(BigInt("19583696538442210257421816149687930861898894457540838395018829873613832108851")), Fp(BigInt("22526875801371184821181570246816236576448644880717020355432045498197577562711")),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("51350284864274176077585216690595295345910970011195603140224124332586682398734")), Fp(BigInt("9195404449948098526566482694993850148148550213325878247570491211174099400997"))
      ) -> FP2Elem(Fp(BigInt("25675142432137088038792608345297647672955485005597801570112062166293341199367")), Fp(BigInt("37097977072797351129681460718676877945486954160474440909723818119019141736390")))
      val result = encryptInstance.pairing.addLineEval(basePointX, basePointY, goodHomogeneousPoint, goodHomogeneousPoint.double)
      result shouldBe expectedGoodResult
    }
    "match 2nd known value" in {
      val expectedGoodResult = FP12Elem.create(
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("55744800738974830414511837562097001444513814113731905690103202632714685000112")),
        Fp(BigInt("5931115851264405664176255926844469633299602620131317110698302035851504058485")),
        Fp(BigInt("5922043367691349962919743457016954000050519680657775073386104333409065506275")),
        Fp(BigInt("20288974314653081232608663556936861878151531295868263204413435854177100288352")),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("26356633409924402912277270815241187276017192428798815740104200671052283049228")),
        Fp(BigInt("15795322029202928214286645072236506167028617449376846994561520041437363044626"))
      ) -> FP2Elem(Fp(BigInt("45317051037626942699433282368426742998780524510558790284447501032407331744487")), Fp(BigInt("57314508651404382971317523526158597484748409902108919167661676452517534974217")))
      val (pointX, pointY) = basePoint.double.double.normalize.value
      val result = encryptInstance.pairing.addLineEval(pointX, pointY, goodHomogeneousPoint.double, goodHomogeneousPoint.double.double)
      result shouldBe expectedGoodResult
    }
  }

  "doubleLineEval" should {
    "match known value" in {
      val expectedGoodResult = FP12Elem.create(
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("17712485624843220480183304963635457557059227558921981718335334461785067564761")),
        Fp(BigInt("60062497247414669535857527984449046910652829387114413501954200738470746113195")),
        Fp(BigInt("22388663537106305339863882629391283032654826869605943340705330045870326159547")),
        Fp(BigInt("53713945989969989737781120925512388913929867004299271526634203788037019854146")),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt(0)), Fp(BigInt(0)),
        Fp(BigInt("20917605796411899317217008737010033956820097935526175686366958730322466630407")), Fp(BigInt("56032303778290759243918533214786117372540626820242016384835510414304520082514"))
      ) -> FP2Elem(Fp(BigInt("42959077746029251525006723739684969849822728021574589629122051878593325351095")), Fp(BigInt("28016151889145379621959266607393058686270313410121008192417755207152260041257")))
      val result = encryptInstance.pairing.doubleLineEval(basePointX, basePointY, goodHomogeneousPoint)
      result shouldBe expectedGoodResult
    }
  }

  "pair " should {
    "match known good value" in {
      val expectedGoodResult = FP12Elem.create(
        Fp(BigInt("20621517740542501009268492188240231175004875885443969425948886451683622135253")),
        Fp(BigInt("34374877744619883729582518521480375735530540362125629015072222432427068254516")),
        Fp(BigInt("3061516916225902041514148805993070634368655849312514173666756917317148753791")),
        Fp(BigInt("36462333850830053304472867079357777410712443208968594405185610332940263631144")),
        Fp(BigInt("61512103449194136219283269928242996434577060883392017268158197606945715641345")),
        Fp(BigInt("6400685679296646713554926627062187315936943674688629293503755450503276487519")),
        Fp(BigInt("53751186939356616119935218564341196608994152768328518524478036628068165341835")),
        Fp(BigInt("24086990466602794093787211540995552936111869178774386613517233502609109093865")),
        Fp(BigInt("61396452992397102589850224464045014903468298857108669606429537125544948220026")),
        Fp(BigInt("15909384434160564083979503677021998800821775569159782381560100961841901513229")),
        Fp(BigInt("60608834117224548548490931258722195552088501100182383267798941700183023164589")),
        Fp(BigInt("17433339776741835027827317970122814431745024562995872600925458287403992082321"))
      )
      encryptInstance.pairing.pair(basePoint, goodHomogeneousPoint) shouldBe expectedGoodResult
    }

    "follow the law pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)" in {
      forAll { a: BigInt =>
        whenever(a != 0) {
          val baseResult = encryptInstance.pairing.pair(basePoint.times(a), goodHomogeneousPoint.times(a))
          baseResult shouldBe encryptInstance.pairing.pair(basePoint.times(a.pow(2)), goodHomogeneousPoint)
          baseResult shouldBe encryptInstance.pairing.pair(basePoint, goodHomogeneousPoint.times(a.pow(2)))
        }
      }
    }
    "follow the law pair(a * P, a * Q) == pair(P, Q) ^ (a^2)" in {
      forAll { a: BigInt =>
        whenever(a != 0) {
          encryptInstance.pairing.pair(basePoint.times(a), goodHomogeneousPoint.times(a)) shouldBe encryptInstance.pairing.pair(basePoint, goodHomogeneousPoint) ^ (a.pow(2))
        }
      }
    }
  }

  "encrypt" should {
    val privateKey = PrivateKey(Fp(BigInt("-22")))
    val ephemeralSecretKey = BigInt("42")
    val plaintext = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
    val publicKey = keyGen(privateKey)
    val encryptResult = encryptInstance.encrypt(publicKey, plaintext, PrivateKey.fromBigInt(ephemeralSecretKey), publicSigningKey, privateSigningKey)
    "round trip known good text" in {
      val decryptResult = encryptInstance.decrypt(privateKey, encryptResult).value
      decryptResult shouldBe plaintext
    }

    "produce the expected signature" in {
      encryptResult.signature shouldBe defaultSignature
    }

    "produce the expected authHash" in {
      encryptResult.payload.authHash shouldBe AuthHash.create(sha256Hash, encryptResult.payload.ephemeralPublicKey, plaintext)
    }

    "round trip with decrypt using Fp" in {
      forAll { (plaintext: FP12Elem[Fp], privateKey: PrivateKey[Fp], ephemeralPrivateKey: PrivateKey[Fp]) =>
        val publicKey = keyGen(privateKey)
        val encryptResult = encryptInstance.encrypt(publicKey, plaintext, ephemeralPrivateKey, publicSigningKey, privateSigningKey)
        val decryptResult = encryptInstance.decrypt(privateKey, encryptResult).value
        decryptResult shouldBe plaintext
      }
    }

    "round trip with decrypt using Fp480" in {
      val internalApi480 = createInternalApi480WithoutSigning(com.ironcorelabs.recrypt.Sha256)
      val keyGen480 = PublicKeyGen(Fp480.curvePoints.generator)
      forAll { (plaintext: FP12Elem[Fp480], privateKey: PrivateKey[Fp480], ephemeralPrivateKey: PrivateKey[Fp480]) =>
        val publicKey = keyGen480(privateKey)
        val encryptResult = internalApi480.encrypt(publicKey, plaintext, ephemeralPrivateKey, publicSigningKey, privateSigningKey)
        val decryptResult = internalApi480.decrypt(privateKey, encryptResult).value
        decryptResult shouldBe plaintext
      }
    }
  }

  "decrypt" should {

    val privateKey = PrivateKey(Fp(BigInt("-8888888888888888888888888888888888")))
    val ephemeralSecretKey = BigInt("3222222232323")
    val plaintext = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
    val publicKey = keyGen(privateKey)
    val encryptResult = encryptInstance.encrypt(publicKey, plaintext, PrivateKey.fromBigInt(ephemeralSecretKey), publicSigningKey, privateSigningKey)
    "fail when verify fails" in {
      val error = createEncryptWithBadVerify.decrypt(privateKey, encryptResult).leftValue
      error shouldBe a[SignatureFailed[_]]
    }
    "fail when authHash is (magically) wrong" in {
      val modifiedPayload = encryptResult.payload.fold[EncryptedValue[Fp]](_.copy(authHash = AuthHash(hex"00ff00ff")), _.copy(authHash = AuthHash(hex"00ff00ff")))
      //This should not be possible as signing should prevent a modified payload, but `encryptInstance` has "always true" signing
      val modifiedEncryptResult = encryptResult.copy(payload = modifiedPayload)
      val decryptErr = encryptInstance.decrypt(privateKey, modifiedEncryptResult).leftValue
      decryptErr shouldBe a[AuthHashMatchFailed[_]]
    }
    "fail when authHash does not match because of wrong private key" in {
      val differentPrivateKey = PrivateKey(Fp(BigInt("-44")))
      val decryptErr = encryptInstance.decrypt(differentPrivateKey, encryptResult).leftValue
      decryptErr shouldBe a[AuthHashMatchFailed[_]]
    }

  }

  "reencrypt" should {
    val salt = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
    val reencryptionPrivate = PrivateKey.fromBigInt(BigInt("22002131259228303741090495322318969764532178674829148099822698556219881568451"))
    val ephemeralPrivateKey = PrivateKey.fromBigInt(BigInt("24550233719269254106556478663938123459765238883583743938937070753673053032673"))
    val privateKey = PrivateKey.fromBigInt(BigInt("43966559432365357341903140497410248873099149633601160471165130153973144042658"))
    val publicKey = keyGen(privateKey)
    val plaintext = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
    val encryptResult = encryptInstance.encrypt(publicKey, plaintext, ephemeralPrivateKey, publicSigningKey, privateSigningKey)
    val raRePrivateKey = PrivateKey.fromBigInt(BigInt("17561965855055966875289582496525889116201409974621952158489640859240156546764"))
    val raReK = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
    val reencryptionKey = encryptInstance.generateReencryptionKey(privateKey, publicKey, reencryptionPrivate, salt, PublicSigningKey.empty, PrivateSigningKey.empty)
    "match known value" in {
      val reencryptedValueOrError = encryptInstance.reencrypt(reencryptionKey, encryptResult, raRePrivateKey, raReK, publicSigningKey, privateSigningKey)
      val reencryptedValue = reencryptedValueOrError.value
      val decryptedValueOrError = encryptInstance.decrypt(privateKey, reencryptedValue)
      val decryptedValue = decryptedValueOrError.value
      decryptedValue shouldBe plaintext
      decryptedValue
    }
    "fail authHash for bad private key" in {
      val reencryptedValueOrError = encryptInstance.reencrypt(reencryptionKey, encryptResult, raRePrivateKey, raReK, publicSigningKey, privateSigningKey)
      val reencryptedValue = reencryptedValueOrError.value
      val differentPrivateKey = PrivateKey(Fp(BigInt("-44")))
      val decryptedValueOrError = encryptInstance.decrypt(differentPrivateKey, reencryptedValue)
      val decryptErr = decryptedValueOrError.leftValue
      decryptErr shouldBe a[AuthHashMatchFailed[_]]
    }

    "roundtrip with decryptN for single level" in {
      forAll { (privateKeyFp: Fp, reencryptionPrivate: PrivateKey[Fp], salt: FP12Elem[Fp], plaintext: FP12Elem[Fp], ephemeralPrivateKey: PrivateKey[Fp], fps: (Fp, FP12Elem[Fp])) =>
        val (_, reencryptionSaltFp) = fps
        val privateKey = PrivateKey(privateKeyFp)
        val fromPublicKey = keyGen(privateKey)
        val toPublicKey = fromPublicKey
        val reencryptionKey = encryptInstance.generateReencryptionKey(privateKey, toPublicKey, reencryptionPrivate, salt, PublicSigningKey.empty, PrivateSigningKey.empty)
        val encryptResult = encryptInstance.encrypt(toPublicKey, plaintext, ephemeralPrivateKey, publicSigningKey, privateSigningKey)
        val reencryptedValueOrError = encryptInstance.reencrypt(reencryptionKey, encryptResult, reencryptionPrivate, reencryptionSaltFp, publicSigningKey, privateSigningKey)
        val reencryptedValue = reencryptedValueOrError.value
        val decryptedValueOrError = encryptInstance.decrypt(privateKey, reencryptedValue)
        val decryptedValue = decryptedValueOrError.value
        decryptedValue shouldBe plaintext
      }
    }

    "compute good authHash" in {
      encryptResult.payload.authHash shouldBe AuthHash.create(sha256Hash, encryptResult.payload.ephemeralPublicKey, plaintext)
      encryptResult.payload.authHash.bytes should not be (sha256Hash(plaintext))
    }

    "fail on bad signature" in {
      val reencryptedValueOrError = createEncryptWithBadVerify.reencrypt(reencryptionKey, encryptResult, raRePrivateKey, raReK, publicSigningKey, privateSigningKey)
      val error = reencryptedValueOrError.leftValue
      error shouldBe a[SignatureFailed[_]]
    }
  }

  "reencryptN" should {
    "match known value" in {
      val salt1 = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
      val reencryptionPrivate = PrivateKey.fromBigInt(BigInt("22002131259228303741090495322318969764532178674829148099822698556219881568451"))
      val ephemeralPrivateKey = PrivateKey.fromBigInt(BigInt("24550233719269254106556478663938123459765238883583743938937070753673053032673"))
      val privateKey = PrivateKey(Fp(BigInt("43966559432365357341903140497410248873099149633601160471165130153973144042658")))
      val publicKey = keyGen(privateKey)
      val privateKey2 = PrivateKey(Fp(BigInt("22266559432365357341903140497410248873090149633601160471165130153973144042608")))
      val publicKey2 = keyGen(privateKey2)
      val privateKey3 = PrivateKey(Fp(BigInt("33333359432365357341903140497410248873090149633601160471165130153973144042608")))
      val publicKey3 = keyGen(privateKey3)

      val plaintext = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
      //First level Encryption
      val encryptResult = encryptInstance.encrypt(publicKey, plaintext, ephemeralPrivateKey, publicSigningKey, privateSigningKey)
      val raRePrivateKey = PrivateKey.fromBigInt(BigInt("17561965855055966875289582496525889116201409974621952158489640859240156546764"))
      val raReK = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
      val reencryptionKey = encryptInstance.generateReencryptionKey(privateKey, publicKey2, reencryptionPrivate, salt1, publicSigningKey, privateSigningKey)
      val reencryptedValueOrError = encryptInstance.reencrypt(reencryptionKey, encryptResult, raRePrivateKey, raReK, publicSigningKey, privateSigningKey)
      //Generate first level reencryption
      val reencryptedValue = reencryptedValueOrError.value

      //Now let's do a 2nd level of reencryption
      val raRePrivateKey2 = PrivateKey.fromBigInt(BigInt("1756196585505596687528958249652588911620140997462195215848000000000"))
      val raReK2 = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
      val salt2 = encryptInstance.generateRthRoot(randomFP12IO.unsafeRunSync)
      val reencryptionPrivate2 = PrivateKey.fromBigInt(BigInt("22002131259228303741090495322318969763333178674829148099822698556219881568451"))
      val reencryptionKey2 = encryptInstance.generateReencryptionKey(privateKey2, publicKey3, reencryptionPrivate2, salt2, publicSigningKey, privateSigningKey)
      val reencryptedValueOrError2 = encryptInstance.reencrypt(reencryptionKey2, reencryptedValue, raRePrivateKey2, raReK2, publicSigningKey, privateSigningKey)
      val reencryptedValue2 = reencryptedValueOrError2.value

      val decryptedValueOrError = encryptInstance.decrypt(privateKey3, reencryptedValue2)
      val decryptedValue = decryptedValueOrError.value
      decryptedValue shouldBe plaintext
    }

    "generateReencryptionKey" should {
      "produce signature that doesn't care about hashedK" in {
        forAll { (publicKey: PublicKey[Fp], privKey: PrivateKey[Fp], diffHashedK: HomogeneousPoint[FP2Elem[Fp]]) =>
          forAll(genReencryptionKey(privKey, publicKey)) { key =>
            val changedKey = key.copy(signature = Signature(hex"deadbeef"), payload = key.payload.copy(hashedK = diffHashedK))
            key.toHashBytes shouldBe changedKey.toHashBytes
          }
        }

      }
    }

    "verifySignedValue" should {
      //An encrypt instance which will fail verify if the messages passed are different.
      val encryptInstanceWithSign = new InternalApi(
        Sha256Hash(com.ironcorelabs.recrypt.Sha256),
        Ed25519Signing((_, message) => Signature(message), (_, message, signature) => message == signature.bytes), Fp.curvePoints
      )
      val pubKeyBytes = hex"dead"
      val origMessage = Fp(hex"beeeeeeeef")
      //Signature manually computed. publicKeyBytes + origMessage
      val signedValue = SignedValue(PublicSigningKey(pubKeyBytes), Signature(pubKeyBytes ++ Hashable[Fp].toByteVector(origMessage)), origMessage)
      "succeed if the payload is the same" in {
        encryptInstanceWithSign.verifySignedValue(signedValue) shouldBe Some(origMessage)
      }

      "fail if the payload is different" in {
        encryptInstanceWithSign.verifySignedValue(signedValue.copy(payload = Fp(hex"dd"))) shouldBe None
      }
      "fail if the publicSigningKey is different" in {
        encryptInstanceWithSign.verifySignedValue(signedValue.copy(publicSigningKey = PublicSigningKey(hex"dd"))) shouldBe None
      }
    }
  }
}

object InternalApiTest {
  val defaultSignature = Signature(hex"deaddeefbeef")
  def createEncryptWithoutSigning(hashFunc: ByteVector => ByteVector): InternalApi[Fp] = new InternalApi(Sha256Hash(hashFunc), Ed25519Signing((_, _) => defaultSignature, (_, _, _) => true), Fp.curvePoints)
  def createInternalApi480WithoutSigning(hashFunc: ByteVector => ByteVector): InternalApi[Fp480] = new InternalApi(Sha256Hash(hashFunc), Ed25519Signing((_, _) => defaultSignature, (_, _, _) => true), Fp480.curvePoints)
  def createEncryptWithBadVerify: InternalApi[Fp] = new InternalApi(Sha256Hash { bytes => bytes }, Ed25519Signing((_, _) => defaultSignature, (_, _, _) => false), Fp.curvePoints)
}
