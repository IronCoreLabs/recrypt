package bench

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._

import com.ironcorelabs.recrypt.internal._
import point.HomogeneousPoint
import cats.implicits._
import cats.effect.unsafe.implicits.global

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class HomogeneousPointBenchmark extends BenchmarkHelper {
  val point = Fp.curvePoints.g1

  @Param(Array("1", "10"))
  var size: Int = 0

  var points: Vector[HomogeneousPoint[FP2Elem[Fp]]] = Vector.empty

  @Setup
  def setup(): Unit = {
    points =
      Vector.fill(size)(randomFp.map(point.times)).sequence.unsafeRunSync()
  }

  @Benchmark
  def add() = points.foldLeft(point)((acc, p) => acc.add(p))

  @Benchmark
  def doublePoint() = points.foldLeft(point)((_, p) => p.double)

  @Benchmark
  def times10() = points.foldLeft(point)((_, p) => p.times(10))
}
