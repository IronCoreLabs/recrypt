package bench

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._

import com.ironcorelabs.recrypt.internal._
import cats.instances.list._
import cats.syntax.traverse._

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.SECONDS)
class GenerateFp12ElemBenchmark extends BenchmarkHelper {
  import Fp.implicits._
  val pairing = new Pairing[Fp]

  @Param(Array("1", "10"))
  var size: Int = 0

  var fp12s: List[FP12Elem[Fp]] = List.empty
  private[this] val fp12Elem = pairing.pair(Fp.curvePoints.generator, Fp.curvePoints.g1)
  //Old, inferior way of doing fp12 generation. Here just for comparison with FinalExp.
  def generateFp12(fp: Fp): FP12Elem[Fp] = fp12Elem ^ fp

  @Setup
  def setup(): Unit = {
    fp12s = List.fill(size)(randomFp12IO).sequence.unsafeRunSync
  }

  @Benchmark
  def generateUsingFinalExp() = fp12s.foreach(pairing.finalExponentiation(_))

  @Benchmark
  def generateUsingFinalExpIncludingIO() = fp12s.foreach(_ => randomFp12IO.map(pairing.finalExponentiation(_)).unsafeRunSync)

  @Benchmark
  def generateUsingRaising() = fp12s.foreach(fp12 => generateFp12(fp12.elem1.elem1.elem1))
}
