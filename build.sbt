import org.typelevel.scalacoptions.ScalacOptions
import ReleaseTransformations._

lazy val scala213 = "2.13.18"

// The LTS line rather than the latest 3.x.
lazy val scala3 = "3.3.9"

// publish := {} doesn't cover sbt-pgp's publishSigned, which is what the release actually uses.
lazy val noPublish = Seq(
  publish / skip := true,
  publish := {},
  publishLocal := {},
  PgpKeys.publishSigned := {},
  publishArtifact := false
)

lazy val coreDependencies = Seq(
  "org.typelevel" %% "spire"       % "0.18.0",
  "org.scodec"    %% "scodec-bits" % "1.2.5",
  "org.typelevel" %% "cats-effect" % "3.7.1"
)

lazy val testDependencies = Seq(
  "org.scalatest"  %% "scalatest"            % "3.2.20",
  "org.scalacheck" %% "scalacheck"           % "1.20.0",
  "org.typelevel"  %% "spire-laws"           % "0.18.0",
  "org.typelevel"  %% "discipline-scalatest" % "2.3.0"
).map(_ % Test)

lazy val recryptSettings = Seq(
  organization := "com.ironcorelabs",
  licenses += ("AGPL-3.0", uri("https://www.gnu.org/licenses/agpl-3.0.txt")),
  scalaVersion := scala213,
  crossScalaVersions := Seq(scala213, scala3),
  semanticdbEnabled := true,
  // Scala 3 emits SemanticDB itself; only Scala 2 needs the plugin pinned to scalafix's build.
  semanticdbVersion := (if (scalaBinaryVersion.value == "3") semanticdbVersion.value else scalafixSemanticdb.revision),
  headerLicense := Some(
    HeaderLicense.Custom(
      """|Copyright (C) 2017-present  IronCore Labs
         |
         |This program is free software: you can redistribute it and/or modify
         |it under the terms of the GNU Affero General Public License as
         |published by the Free Software Foundation, either version 3 of the
         |License, or (at your option) any later version.
         |
         |This program is distributed in the hope that it will be useful,
         |but WITHOUT ANY WARRANTY; without even the implied warranty of
         |MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
         |GNU Affero General Public License for more details.
         |
         |You should have received a copy of the GNU Affero General Public License
         |along with this program.  If not, see <http://www.gnu.org/licenses/>.""".stripMargin
    )
  ),
  libraryDependencies ++= coreDependencies ++ testDependencies,
  // Release configuration
  releasePublishArtifactsAction := PgpKeys.publishSigned.value,
  releaseCrossBuild := true,
  releaseProcess := Seq[ReleaseStep](
    checkSnapshotDependencies,
    inquireVersions,
    runClean,
    runTest,
    setReleaseVersion,
    commitReleaseVersion,
    tagRelease,
    releaseStepCommandAndRemaining("+publishSigned"),
    releaseStepCommand("sonaRelease"),
    setNextVersion,
    commitNextVersion,
    pushChanges
  ),
  isSnapshot := version.value.endsWith("SNAPSHOT"),
  homepage := Some(uri("http://github.com/ironcorelabs/recrypt")),
  // Snapshots go straight to the Central snapshot repo; releases stage locally so the whole cross-built
  // bundle uploads as one unit from the sonaRelease step above.
  publishTo := {
    if (isSnapshot.value) Some("central-snapshots".at("https://central.sonatype.com/repository/maven-snapshots/"))
    else localStaging.value
  },
  publishMavenStyle := true,
  Test / publishArtifact := false,
  pomIncludeRepository := { _ => false },
  scmInfo := Some(ScmInfo(uri("https://github.com/ironcorelabs/recrypt"), "git@github.com:ironcorelabs/recrypt.git")),
  developers := List(
    Developer("coltfred", "Colt Frederickson", "coltfred+github@gmail.com", uri("http://github.com/coltfred"))
  ),
  coverageMinimumStmtTotal := 80,
  coverageFailOnMinimum := true,
  Test / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-oD"),
  Test / tpolecatExcludeOptions += ScalacOptions.warnNonUnitStatement,
  // Throw on uninitialized field access. Scala 3 checks it at compile time, and renamed the flag
  // -Wsafe-init in 3.5, so bumping scala3 off 3.3 means renaming this.
  scalacOptions += (if (scalaBinaryVersion.value == "3") "-Ysafe-init" else "-Xcheckinit")
)

// Can't .aggregate(benchmark): it dependsOn recrypt, so sbt sees a cycle and drops the aggregation
// without a word, and root compile/test skips it. CI runs it explicitly instead.
lazy val recrypt = project
  .in(file("."))
  .settings(moduleName := "recrypt-core")
  .settings(recryptSettings)

//Benchmark target for running perf tests.
lazy val benchmark = project
  .in(file("benchmark"))
  .dependsOn(recrypt)
  .settings(name := "recrypt-benchmark")
  .settings(recryptSettings*)
  .settings(coverageEnabled := false)
  .settings(noPublish*)
  .settings(
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcprov-jdk18on" % "1.87"
    )
  )
  .enablePlugins(JmhPlugin)
