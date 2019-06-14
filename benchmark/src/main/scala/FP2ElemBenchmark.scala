package bench

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._

import com.ironcorelabs.recrypt.internal.Fp
import com.ironcorelabs.recrypt.internal.FP2Elem

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class FP2ElemBenchmark extends BenchmarkHelper {
  import Fp.implicits._
  val point = FP2Elem(
    Fp(BigInt("25743265030535080187440590897139396943782163562799308681850377411492232521347")),
    Fp(BigInt("34056889713323967780338301808336650802977437253339894663986165323395183925712"))
  )

  @Param(Array("1", "10"))
  var size: Int = 0

  var elements: Vector[FP2Elem[Fp]] = Vector.empty

  @Setup
  def setup(): Unit = {
    elements = Vector.fill(size)(point)
  }

  @Benchmark
  def addingFP2 = elements.foldLeft(point)((acc, p) => acc + p)

  @Benchmark
  def timesFP2 = elements.foldLeft(point)((acc, p) => acc * p)

  @Benchmark
  def squareFP2 = elements.foldLeft(point)((acc, _) => acc.square)

  @Benchmark
  def scaleFp2Times100 = elements.foldLeft(point)((acc, _) => acc * 100)

  @Benchmark
  def powFp2By100 = elements.foldLeft(point)((acc, _) => acc ^ 100)
}
