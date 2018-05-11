package bench

import cats.effect.IO
import scodec.bits.ByteVector
import com.ironcorelabs.recrypt.internal.{ Fp, FP12Elem }
import cats.implicits._
import Fp.implicits._

trait BenchmarkHelper {
  val randomBytesIO: IO[ByteVector] = {
    //Start with a known value, we'll just add one to it each time
    var i = 100L
    val hashFunc = java.security.MessageDigest.getInstance("SHA-256").digest(_: Array[Byte])
    IO {
      i += 1
      ByteVector.view(hashFunc(List(i.byteValue).toArray))
    }
  }

  val randomFp = randomBytesIO.map(Fp(_))

  val randomFp12IO: IO[FP12Elem[Fp]] = {
    val randCoefList = List.fill(12)(randomFp).sequence
    randCoefList.map {
      case fp1 :: fp2 :: fp3 :: fp4 :: fp5 :: fp6 :: fp7 :: fp8 :: fp9 :: fp10 :: fp11 :: fp12 :: Nil =>
        FP12Elem.create(fp1, fp2, fp3, fp4, fp5, fp6, fp7, fp8, fp9, fp10, fp11, fp12)
      case _ => throw new Exception("Unless someone breaks the randCoefList above, this can't happen.")
    }
  }
}
