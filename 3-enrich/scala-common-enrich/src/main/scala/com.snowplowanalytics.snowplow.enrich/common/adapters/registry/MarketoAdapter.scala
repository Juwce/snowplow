/*
 * Copyright (c) 2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common
package adapters
package registry

import cats.instances.option._
import cats.syntax.either._
import com.snowplowanalytics.iglu.client.{Resolver, SchemaKey}
import io.circe._
import io.circe.parser._
import org.joda.time.DateTimeZone
import org.joda.time.format.DateTimeFormat
import scalaz._
import Scalaz._

import loaders.CollectorPayload
import utils.{JsonUtils => JU}

/**
 * Transforms a collector payload which conforms to a known version of the Marketo webhook into raw
 * events.
 */
object MarketoAdapter extends Adapter {
  // Vendor name for Failure Message
  private val VendorName = "Marketo"

  // Expected content type for a request body
  private val ContentType = "application/json"

  // Tracker version for an Marketo webhook
  private val TrackerVersion = "com.marketo-v1"

  // Schemas for reverse-engineering a Snowplow unstructured event
  private val EventSchemaMap = Map(
    "event" -> SchemaKey("com.marketo", "event", "jsonschema", "2-0-0").toSchemaUri
  )

  // Datetime format used by Marketo
  private val MarketoDateTimeFormat =
    DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss").withZone(DateTimeZone.UTC)

  /**
   * Returns a validated JSON payload event. Converts all date-time values to a valid format.
   * The payload will be validated against marketo "event" schema.
   * @param json The JSON payload sent by Marketo
   * @param payload Rest of the payload details
   * @return a validated JSON payload on Success, or a NEL
   */
  private def payloadBodyToEvent(json: String, payload: CollectorPayload): Validated[RawEvent] =
    for {
      parsed <- parse(json) match {
        case Right(json) => json.successNel
        case Left(e) => s"$VendorName event failed to parse into JSON: [${e.getMessage}]".failureNel
      }

      parsedConverted <- parsed.asObject match {
        case Some(obj) =>
          val dateFields = List(
            "acquisition_date",
            "created_at",
            "email_suspended_at",
            "last_referred_enrollment",
            "last_referred_visit",
            "updated_at",
            "datetime",
            "last_interesting_moment_date"
          )
          val newValues = dateFields
            .map(name => (name, obj.kleisli.andThen(turnFieldIntoDate).run(name)))
          newValues
            .foldLeft(obj) { case (o, (n, v)) => v.map(o.add(n, _)).getOrElse(o) }
            .successNel
        case _ => s"$VendorName event is not a json object".failureNel
      }

      // The payload doesn't contain a "type" field so we're constraining the eventType to be of
      // type "event"
      eventType = Some("event")
      schema <- lookupSchema(eventType, VendorName, EventSchemaMap)
      params = toUnstructEventParams(
        TrackerVersion,
        toMap(payload.querystring),
        schema,
        parsedConverted,
        "srv")
      rawEvent = RawEvent(
        api = payload.api,
        parameters = params,
        contentType = payload.contentType,
        source = payload.source,
        context = payload.context)
    } yield rawEvent

  private val turnFieldIntoDate: Kleisli[Option, Json, Json] =
    Kleisli(
      (json: Json) =>
        json.asString
          .map { v =>
            Either
              .catchNonFatal(Json.fromString(JU.toJsonSchemaDateTime(v, MarketoDateTimeFormat)))
              .getOrElse(Json.fromString(v))
        })

  /**
   * Converts a CollectorPayload instance into raw events.
   * Marketo event contains no "type" field and since there's only 1 schema the function
   * lookupschema takes the eventType parameter as "event".
   * We expect the type parameter to match the supported events, else
   * we have an unsupported event type.
   * @param payload The CollectorPayload containing one or more raw events
   * @param resolver (implicit) The Iglu resolver used for schema lookup and validation. Not used
   * @return a Validation boxing either a NEL of RawEvents on Success, or a NEL of Failure Strings
   */
  override def toRawEvents(payload: CollectorPayload)(implicit r: Resolver): ValidatedRawEvents =
    (payload.body, payload.contentType) match {
      case (None, _) => s"Request body is empty: no $VendorName event to process".failureNel
      case (Some(body), _) => {
        val event = payloadBodyToEvent(body, payload)
        rawEventsListProcessor(List(event))
      }
    }
}
