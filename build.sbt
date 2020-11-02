import org.scalajs.sbtplugin.ScalaJSPlugin.AutoImport.scalaJSModuleKind
import scalariform.formatter.preferences._

lazy val noPublish = Seq(
  publish := {},
  publishLocal := {},
  publishArtifact := false)

lazy val recryptSettings = Seq(
  organization := "com.ironcorelabs",
  licenses += ("AGPL-3.0", new URL("https://www.gnu.org/licenses/agpl-3.0.txt")),
  scalaVersion := "2.12.11",
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
    "org.scalatest" %%% "scalatest" % "3.0.9" % "test",
    "org.scalacheck" %%% "scalacheck" % "1.15.0" % "test",
    "org.typelevel" %%% "spire-laws" % "0.14.1" % "test",
    "org.typelevel" %%% "discipline" % "0.10.0" % "test"
  ) ++ Seq( // Core dependencies.
    "org.typelevel" %%% "spire" % "0.15.0",
    "org.scodec" %%% "scodec-bits" % "1.1.18",
    "org.typelevel" %%% "cats-effect" % "2.1.4"
  ),
  //List is from https://tpolecat.github.io/2017/04/25/scalac-flags.html
  scalacOptions ++= Seq(
    "-deprecation",                      // Emit warning and location for usages of deprecated APIs.
    "-encoding", "utf-8",                // Specify character encoding used by source files.
    "-explaintypes",                     // Explain type errors in more detail.
    "-feature",                          // Emit warning and location for usages of features that should be imported explicitly.
    "-language:existentials",            // Existential types (besides wildcard types) can be written and inferred
    "-language:experimental.macros",     // Allow macro definition (besides implementation and application)
    "-language:higherKinds",             // Allow higher-kinded types
    "-language:implicitConversions",     // Allow definition of implicit functions called views
    "-unchecked",                        // Enable additional warnings where generated code depends on assumptions.
    //This is left here to keep it close to tpolecat's original. It's added in jvm, but causes js to bloat.
    //"-Xcheckinit",                       // Wrap field accessors to throw an exception on uninitialized access.
    "-Xfatal-warnings",                  // Fail the compilation if there are any warnings.
    "-Xfuture",                          // Turn on future language features.
    "-Xlint:adapted-args",               // Warn if an argument list is modified to match the receiver.
    "-Xlint:by-name-right-associative",  // By-name parameter of right associative operator.
    "-Xlint:constant",                   // Evaluation of a constant arithmetic expression results in an error.
    "-Xlint:delayedinit-select",         // Selecting member of DelayedInit.
    "-Xlint:doc-detached",               // A Scaladoc comment appears to be detached from its element.
    "-Xlint:inaccessible",               // Warn about inaccessible types in method signatures.
    "-Xlint:infer-any",                  // Warn when a type argument is inferred to be `Any`.
    "-Xlint:missing-interpolator",       // A string literal appears to be missing an interpolator id.
    "-Xlint:nullary-override",           // Warn when non-nullary `def f()' overrides nullary `def f'.
    "-Xlint:nullary-unit",               // Warn when nullary methods return Unit.
    "-Xlint:option-implicit",            // Option.apply used implicit view.
    "-Xlint:package-object-classes",     // Class or object defined in package object.
    "-Xlint:poly-implicit-overload",     // Parameterized overloaded implicit methods are not visible as view bounds.
    "-Xlint:private-shadow",             // A private field (or class parameter) shadows a superclass field.
    "-Xlint:stars-align",                // Pattern sequence wildcard must align with sequence component.
    "-Xlint:type-parameter-shadow",      // A local type parameter shadows a type already in scope.
    "-Xlint:unsound-match",              // Pattern match may not be typesafe.
    "-Yno-adapted-args",                 // Do not adapt an argument list (either by inserting () or creating a tuple) to match the receiver.
    "-Ypartial-unification",             // Enable partial unification in type constructor inference
    "-Ywarn-dead-code",                  // Warn when dead code is identified.
    "-Ywarn-extra-implicit",             // Warn when more than one implicit parameter section is defined.
    "-Ywarn-inaccessible",               // Warn about inaccessible types in method signatures.
    "-Ywarn-infer-any",                  // Warn when a type argument is inferred to be `Any`.
    "-Ywarn-nullary-override",           // Warn when non-nullary `def f()' overrides nullary `def f'.
    "-Ywarn-nullary-unit",               // Warn when nullary methods return Unit.
    "-Ywarn-numeric-widen",              // Warn when numerics are widened.
    "-Ywarn-unused:implicits",           // Warn if an implicit parameter is unused.
    "-Ywarn-unused:imports",             // Warn if an import selector is not referenced.
    "-Ywarn-unused:locals",              // Warn if a local definition is unused.
    "-Ywarn-unused:params",              // Warn if a value parameter is unused.
    "-Ywarn-unused:patvars",             // Warn if a variable bound in a pattern is unused.
    "-Ywarn-unused:privates",            // Warn if a private member is unused.
    "-Ywarn-value-discard"               // Warn when non-Unit expression results are unused.
  ),
  // HACK: without these lines, the console is basically unusable,
  // since all imports are reported as being unused (and then become
  // fatal errors).
  scalacOptions in (Compile, console) ~= { _.filterNot(_.startsWith("-Xlint")).filterNot(_.startsWith("-Ywarn")) },
  scalacOptions in (Test, console) := (scalacOptions in (Compile, console)).value,

  //Release configuration
  releasePublishArtifactsAction := PgpKeys.publishSigned.value,
  isSnapshot := version.value endsWith "SNAPSHOT",
  homepage := Some(url("http://github.com/ironcorelabs/recrypt")),
  useGpg := true,
  publishTo := Some(
    if (isSnapshot.value)
      Opts.resolver.sonatypeSnapshots
    else
      Opts.resolver.sonatypeStaging),
  publishMavenStyle := true,
  publishArtifact in Test := false,
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
  coverageMinimum := 80,
  coverageFailOnMinimum := true,
  //Workaround for issue: https://github.com/scalastyle/scalastyle-sbt-plugin/issues/47
  (scalastyleSources in Compile) ++= (unmanagedSourceDirectories in Compile).value)

lazy val commonJvmSettings = Seq(
  testOptions in Test += Tests.Argument(TestFrameworks.ScalaTest, "-oDF"),
  libraryDependencies ++= Seq(
      "com.ironcorelabs" %%% "cats-scalatest" % "2.4.0" % "test"
    ),
  scalacOptions ++= Seq(
    "-Xcheckinit" // Wrap field accessors to throw an exception on uninitialized access.
  )
)

lazy val commonJsSettings = Seq(
  scalaJSStage in Global := FastOptStage,
  parallelExecution := false,
  jsEnv := new org.scalajs.jsenv.nodejs.NodeJSEnv(),
  scalacOptions ++= Seq("-P:scalajs:sjsDefinedByDefault"),
  scalaJSModuleKind := (if(scala.sys.env.get("SCALA_JS_COMMON_JS").isDefined) ModuleKind.CommonJSModule else ModuleKind.NoModule),
  // batch mode decreases the amount of memory needed to compile scala.js code
  scalaJSOptimizerOptions := scalaJSOptimizerOptions.value.withBatchMode(scala.sys.env.get("TRAVIS").isDefined))

//Master project which aggregates all the sub projects.
lazy val recrypt = project
  .in(file("."))
  .settings(moduleName := "recrypt")
  .settings(recryptSettings)
  .settings(noPublish: _*)
  .aggregate(coreJVM, coreJS, benchmark)
  .dependsOn(coreJVM, coreJS, benchmark)

//The core project, which has both js and JVM targets (under .js and .jvm)
lazy val core =  crossProject.crossType(RecryptCrossType)
  .in(file("core"))
  .settings(name := "recrypt-core")
  .settings(moduleName := "recrypt-core")
  .settings(recryptSettings: _*)
  .disablePlugins(JmhPlugin)
  .jsSettings(commonJsSettings: _*)
  .jsSettings(coverageEnabled := false)
  .jvmSettings(commonJvmSettings: _*)
  .jvmConfigure(_.enablePlugins(AutomateHeaderPlugin))
  .jsConfigure(_.enablePlugins(AutomateHeaderPlugin))

//Targets that are JVM and js specific. Really just aliases.
lazy val coreJVM = core.jvm
lazy val coreJS = core.js

//Benchmark target for running perf tests.
lazy val benchmark = project.in(file("benchmark"))
  .dependsOn(coreJVM)
  .settings(name := "recrypt-benchmark")
  .settings(recryptSettings: _*)
  .settings(coverageEnabled := false)
  .settings(noPublish: _*)
  .settings(  libraryDependencies ++= Seq(
      "org.abstractj.kalium" % "kalium" % "0.8.0"
    ))
  .enablePlugins(JmhPlugin)
