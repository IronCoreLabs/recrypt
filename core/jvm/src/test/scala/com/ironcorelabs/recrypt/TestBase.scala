/*
 * Copyright (C) 2017-present  IronCore Labs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.ironcorelabs.recrypt

import org.scalatest.{ BeforeAndAfterAll, Matchers, OptionValues, WordSpec }
import cats.scalatest.EitherValues
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalacheck.{ Prop, Properties }

abstract class TestBase
  extends WordSpec
  with Matchers
  with OptionValues
  with BeforeAndAfterAll
  with GeneratorDrivenPropertyChecks
  with EitherValues {
  //scalacheck dropped properties inheriting Prop in 1.13.
  //see https://github.com/rickynils/scalacheck/issues/254
  def propertiesToProp(properties: Properties) = Prop.all(properties.properties.map(_._2): _*)
  implicit def untypedNoShrink[A] = org.scalacheck.Shrink[A] { _ => Stream.empty }

}
