addSbtPlugin("org.scalastyle"           %% "scalastyle-sbt-plugin" % "1.0.0")
addSbtPlugin("org.scalariform"           % "sbt-scalariform"       % "1.8.3")
addSbtPlugin("org.scoverage"             % "sbt-scoverage"         % "2.4.3")
addSbtPlugin("com.github.sbt"            % "sbt-release"           % "1.4.0")
addSbtPlugin("pl.project13.scala"        % "sbt-jmh"               % "0.4.8")
addSbtPlugin("com.github.sbt"            % "sbt-pgp"               % "2.3.1")
addSbtPlugin("com.github.sbt"         % "sbt-header"            % "5.11.0")
addSbtPlugin("org.xerial.sbt"            % "sbt-sonatype"          % "3.12.2")
addSbtPlugin("org.typelevel"             % "sbt-tpolecat"          % "0.5.2")

// workaround for conflict between sbt-scoverage and scalastyle-sbt-plugin
// https://github.com/scala/bug/issues/12632
ThisBuild / libraryDependencySchemes ++= Seq(
  "org.scala-lang.modules" %% "scala-xml" % VersionScheme.Always
)
