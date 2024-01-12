addSbtPlugin("org.scalastyle"           %% "scalastyle-sbt-plugin" % "1.0.0")
addSbtPlugin("org.scalariform"           % "sbt-scalariform"       % "1.8.3")
addSbtPlugin("org.scoverage"             % "sbt-scoverage"         % "2.0.9")
addSbtPlugin("pl.project13.scala"        % "sbt-jmh"               % "0.4.7")
addSbtPlugin("com.github.sbt"            % "sbt-release"           % "1.1.0")
addSbtPlugin("com.github.sbt"            % "sbt-pgp"               % "2.2.1")
addSbtPlugin("de.heikoseeberger"         % "sbt-header"            % "5.10.0")
addSbtPlugin("org.xerial.sbt"            % "sbt-sonatype"          % "3.10.0")
addSbtPlugin("org.typelevel"             % "sbt-tpolecat"          % "0.5.0")

// workaround for conflict between sbt-scoverage and scalastyle-sbt-plugin
// https://github.com/scala/bug/issues/12632
ThisBuild / libraryDependencySchemes ++= Seq(
  "org.scala-lang.modules" %% "scala-xml" % VersionScheme.Always
)
