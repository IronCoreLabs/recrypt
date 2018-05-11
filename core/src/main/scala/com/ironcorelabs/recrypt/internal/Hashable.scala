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

package com.ironcorelabs.recrypt.internal

import scodec.bits.{ ByteOrdering, ByteVector }
import cats._
import cats.syntax.contravariant._
import cats.data.NonEmptyVector
/**
 * Typeclass for converting A to a stable byte representation which is used for hashing, which means it will stay consistent
 * regardless of the changes to the class.
 *
 * Note that the idea of this Typeclass is to capture the shape of types, *not* to disambiguate between types of the
 * same shape. This means for instance that a case class with 2 members might have the same "Hashable" value
 * as a 2 tuple with the same members.
 */
abstract class Hashable[A] {
  def apply(a: A): ByteVector = toByteVector(a)
  def toByteVector(a: A): ByteVector
}

object Hashable {
  def apply[A](implicit instance: Hashable[A]): Hashable[A] = instance
  def by[A](f: A => ByteVector): Hashable[A] = (a: A) => f(a)

  implicit def instance: Contravariant[Hashable] = new Contravariant[Hashable] {
    def contramap[A, B](fa: Hashable[A])(f: B => A): Hashable[B] = Hashable.by { b: B => fa(f(b)) }
  }

  implicit val hashableInt: Hashable[Int] = by(i => ByteVector.fromInt(i, 4, ByteOrdering.BigEndian))

  implicit val hashableByte: Hashable[Byte] = by(ByteVector.fromByte)

  implicit val hashableBigInt: Hashable[BigInt] = by(bigInt => ByteVector.view(bigInt.toByteArray))

  implicit val hashableString: Hashable[String] = by(s => ByteVector.view(s.getBytes("UTF-8")))

  implicit def hashableVector[A](implicit hashableA: Hashable[A]): Hashable[Vector[A]] = Hashable.by[Vector[A]] {
    _.foldLeft(ByteVector.empty) { (acc, a) => hashableA.toByteVector(a) ++ acc }
  }

  implicit def hashableNonEmptyVector[A: Hashable]: Hashable[NonEmptyVector[A]] = Hashable[Vector[A]].contramap(_.toVector)

  implicit def hashableTuple2[A, B](implicit
    hashableA: Hashable[A],
    hashableB: Hashable[B]): Hashable[(A, B)] = Hashable.by {
    case (a, b) => hashableA(a) ++ hashableB(b)
  }

  implicit def hashableTuple3[A, B, C](implicit
    hashableA: Hashable[A],
    hashableB: Hashable[B],
    hashableC: Hashable[C]): Hashable[(A, B, C)] = Hashable.by {
    case (a, b, c) => hashableA(a) ++ hashableB(b) ++ hashableC(c)
  }

  implicit def hashableTuple4[A, B, C, D](implicit
    hashableA: Hashable[A],
    hashableB: Hashable[B],
    hashableC: Hashable[C],
    hashableD: Hashable[D]): Hashable[(A, B, C, D)] = Hashable.by {
    case (a, b, c, d) => hashableA(a) ++ hashableB(b) ++ hashableC(c) ++ hashableD(d)
  }

  implicit def hashableTuple5[A, B, C, D, E](implicit
    hashableA: Hashable[A],
    hashableB: Hashable[B],
    hashableC: Hashable[C],
    hashableD: Hashable[D],
    hashableE: Hashable[E]): Hashable[(A, B, C, D, E)] = Hashable.by {
    case (a, b, c, d, e) => hashableA(a) ++ hashableB(b) ++ hashableC(c) ++ hashableD(d) ++ hashableE(e)
  }

  implicit def hashable[A](implicit hashableA: Hashable[A]): Hashable[Option[A]] = Hashable.by { maybeA =>
    maybeA.map(hashableA(_)).getOrElse(ByteVector(0))
  }
}
