import scalariform.formatter.preferences._
import org.typelevel.scalacoptions.ScalacOptions
import xerial.sbt.Sonatype.sonatypeCentralHost
import ReleaseTransformations._

lazy val noPublish = Seq(
  publish := {},
  publishLocal := {},
  publishArtifact := false)

lazy val recryptSettings = Seq(
  organization := "com.ironcorelabs",
  licenses += ("AGPL-3.0", new URL("https://www.gnu.org/licenses/agpl-3.0.txt")),
  scalaVersion := "2.13.16",
  crossScalaVersions := Seq(scalaVersion.value, "2.12.20"),
  headerLicense := Some(HeaderLicense.Custom(
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
  )),
  scalariformPreferences := scalariformPreferences.value
  .setPreference(DanglingCloseParenthesis, Preserve),

  // Test
  libraryDependencies ++= Seq(
    "org.scalatest" %% "scalatest" % "3.2.19" % "test",
    "org.scalacheck" %% "scalacheck" % "1.18.1" % "test",
    "org.typelevel" %% "spire-laws" % "0.17.0" % "test",
    "org.typelevel" %% "discipline-scalatest" % "2.3.0" %"test",
    ) ++ Seq( // Core dependencies.
    "org.typelevel" %% "spire" % "0.17.0",
    "org.scodec" %% "scodec-bits" % "1.2.4",
    "org.typelevel" %% "cats-effect" % "3.6.2",
  ),
  //Release configuration
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
    releaseStepCommand("sonatypeBundleRelease"),
    setNextVersion,
    commitNextVersion,
    pushChanges
  ),
  isSnapshot := version.value endsWith "SNAPSHOT",
  homepage := Some(url("http://github.com/ironcorelabs/recrypt")),
  sonatypeCredentialHost := sonatypeCentralHost,
  publishTo := sonatypePublishToBundle.value,
  publishMavenStyle := true,
  Test / publishArtifact := false,
  pomIncludeRepository := { _ => false },
  scmInfo := Some(ScmInfo(url("https://github.com/ironcorelabs/recrypt"), "git@github.com:ironcorelabs/recrypt.git")),
  pomExtra := (
      <developers>
        {
        Seq(
          ("coltfred", "Colt Frederickson")
        ).map {
          case (id, name) =>
            <developer>
              <id>{id}</id>
              <name>{name}</name>
              <url>http://github.com/{id}</url>
            </developer>
        }
      }
      </developers>
    ),
  coverageMinimumStmtTotal := 80,
  coverageFailOnMinimum := true,
  //Workaround for issue: https://github.com/scalastyle/scalastyle-sbt-plugin/issues/47
  (Compile / scalastyleSources) ++= (Compile / unmanagedSourceDirectories).value,
    Test / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-oDF"),
  Test / tpolecatExcludeOptions += ScalacOptions.warnNonUnitStatement,
  libraryDependencies ++= Seq(
      "com.ironcorelabs" %% "cats-scalatest" % "3.1.1" % "test"
    ),
  scalacOptions ++= Seq(
    "-Xcheckinit" // Wrap field accessors to throw an exception on uninitialized access.
  ))


lazy val recrypt = project
  .in(file("."))
  .settings(moduleName := "recrypt-core")
  .settings(recryptSettings)


//Benchmark target for running perf tests.
lazy val benchmark = project.in(file("benchmark"))
  .dependsOn(recrypt)
  .settings(name := "recrypt-benchmark")
  .settings(recryptSettings: _*)
  .settings(coverageEnabled := false)
  .settings(noPublish: _*)
  .settings(  libraryDependencies ++= Seq(
      "org.abstractj.kalium" % "kalium" % "0.8.0"
    ))
  .enablePlugins(JmhPlugin)
