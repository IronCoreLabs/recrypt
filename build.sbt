import scalariform.formatter.preferences._
import org.typelevel.scalacoptions.ScalacOptions

lazy val noPublish =
  Seq(publish := {}, publishLocal := {}, publishArtifact := false)

lazy val recryptSettings = Seq(
  organization := "com.ironcorelabs",
  licenses += ("AGPL-3.0", new URL(
    "https://www.gnu.org/licenses/agpl-3.0.txt"
  )),
  scalaVersion := "2.13.12",
  crossScalaVersions ++= Seq("2.13.12", "3.3.1"),
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
  scalariformPreferences := scalariformPreferences.value
    .setPreference(DanglingCloseParenthesis, Preserve),

  // Test
  libraryDependencies ++= Seq(
    "org.scalatest" %% "scalatest" % "3.2.17" % "test",
    "org.scalacheck" %% "scalacheck" % "1.17.0" % "test",
    "org.typelevel" %% "spire-laws" % "0.18.0" % "test",
    "org.typelevel" %% "discipline-scalatest" % "2.2.0" % "test"
  ) ++ Seq( // Core dependencies.
    "org.typelevel" %% "spire" % "0.18.0",
    "org.scodec" %% "scodec-bits" % "1.1.38",
    "org.typelevel" %% "cats-effect" % "3.5.3"
  ),
  // Release configuration
  releasePublishArtifactsAction := PgpKeys.publishSigned.value,
  isSnapshot := version.value endsWith "SNAPSHOT",
  homepage := Some(url("http://github.com/ironcorelabs/recrypt")),
  publishMavenStyle := true,
  Test / publishArtifact := false,
  pomIncludeRepository := { _ => false },
  scmInfo := Some(
    ScmInfo(
      url("https://github.com/ironcorelabs/recrypt"),
      "git@github.com:ironcorelabs/recrypt.git"
    )
  ),
  pomExtra := (
    <developers>
        {
      Seq(
        ("coltfred", "Colt Frederickson")
      ).map { case (id, name) =>
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
  // Workaround for issue: https://github.com/scalastyle/scalastyle-sbt-plugin/issues/47
  (Compile / scalastyleSources) ++= (Compile / unmanagedSourceDirectories).value,
  Test / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-oDF"),
  libraryDependencies ++= Seq(
    "com.ironcorelabs" %% "cats-scalatest" % "3.1.1" % "test"
  ),
  scalacOptions ++= {
    Seq(
      "-encoding",
      "UTF-8",
      "-feature",
      "-language:implicitConversions"
      // disabled during the migration
      // "-Xfatal-warnings"
    ) ++
      (CrossVersion.partialVersion(scalaVersion.value) match {
        case Some((3, _)) =>
          Seq(
            "-unchecked",
            "-source:3.0-migration"
          )
        case _ =>
          Seq(
            "-deprecation",
            "-Xfatal-warnings",
            "-Wunused:imports,privates,locals",
            "-Wvalue-discard"
          )
      })
  }
)

lazy val recrypt = project
  .in(file("."))
  .settings(moduleName := "recrypt-core")
  .settings(recryptSettings)

//Benchmark target for running perf tests.
lazy val benchmark = project
  .in(file("benchmark"))
  .dependsOn(recrypt)
  .settings(name := "recrypt-benchmark")
  .settings(recryptSettings: _*)
  .settings(coverageEnabled := false)
  .settings(noPublish: _*)
  .settings(
    libraryDependencies ++= Seq(
      "org.abstractj.kalium" % "kalium" % "0.8.0"
    )
  )
  .enablePlugins(JmhPlugin)
