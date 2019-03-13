/*
 * Copyright (c) 2012-2019 Snowplow Analytics Ltd. All rights reserved.
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
package enrichments.registry

import java.net.UnknownHostException

import scala.util.control.NonFatal

import com.snowplowanalytics.forex.oerclient._
import com.snowplowanalytics.forex.{Forex, ForexConfig}
import com.snowplowanalytics.iglu.client.{SchemaCriterion, SchemaKey}
import com.snowplowanalytics.iglu.client.validation.ProcessingMessageMethods._
import io.circe._
import org.joda.time.DateTime
import scalaz._
import Scalaz._

import utils.ScalazCirceUtils

/** Companion object. Lets us create an CurrencyConversionEnrichment instance from a Json. */
object CurrencyConversionEnrichmentConfig extends ParseableEnrichment {

  val supportedSchema =
    SchemaCriterion(
      "com.snowplowanalytics.snowplow",
      "currency_conversion_config",
      "jsonschema",
      1,
      0)

  // Creates a CurrencyConversionEnrichment instance from a JValue
  def parse(
    config: Json,
    schemaKey: SchemaKey
  ): ValidatedNelMessage[CurrencyConversionEnrichment] =
    isParseable(config, schemaKey).flatMap { conf =>
      (for {
        apiKey <- ScalazCirceUtils.extract[String](config, "parameters", "apiKey")
        baseCurrency <- ScalazCirceUtils.extract[String](config, "parameters", "baseCurrency")
        accountType <-
          ScalazCirceUtils.extract[String](config, "parameters", "accountType").flatMap {
            case "DEVELOPER" => DeveloperAccount.success
            case "ENTERPRISE" => EnterpriseAccount.success
            case "UNLIMITED" => UnlimitedAccount.success
            // Should never happen (prevented by schema validation)
            case s =>
              "accountType [%s] is not one of DEVELOPER, ENTERPRISE, and UNLIMITED"
                .format(s)
                .toProcessingMessage
                .fail
          }
        rateAt <- ScalazCirceUtils.extract[String](config, "parameters", "rateAt")
        enrich = CurrencyConversionEnrichment(accountType, apiKey, baseCurrency, rateAt)
      } yield enrich).toValidationNel
    }
}

/**
 * Configuration for a currency_conversion enrichment
 * @param apiKey OER authentication
 * @param baseCurrency Currency to which to convert
 * @param rateAt Which exchange rate to use - "EOD_PRIOR" for "end of previous day".
 */
final case class CurrencyConversionEnrichment(
  accountType: AccountType,
  apiKey: String,
  baseCurrency: String,
  rateAt: String
) extends Enrichment {
  val fx = Forex(ForexConfig(), OerClientConfig(apiKey, accountType))

  /**
   * Attempt to convert if the initial currency and value are both defined
   * @param inputCurrency Option boxing the initial currency if it is present
   * @param value Option boxing the amount to convert
   * @return None.success if the inputs were not both defined,
   * otherwise Validation[Option[_]] boxing the result of the conversion
   */
  private def performConversion(
    initialCurrency: Option[String],
    value: Option[Double],
    tstamp: DateTime
  ): Validation[String, Option[String]] =
    (initialCurrency, value) match {
      case (Some(ic), Some(v)) =>
        fx.convert(v, ic).to(baseCurrency).at(tstamp) match {
          case Left(l) =>
            val errorType = l.errorType.getClass.getSimpleName.replace("$", "")
            s"Open Exchange Rates error, type: [$errorType], message: [${l.errorMessage}]".failure
          case Right(s) => (s.getAmount().toPlainString()).some.success
        }
      case _ => None.success
    }

  /**
   * Converts currency using Scala Forex
   * @param trCurrency Initial transaction currency
   * @param trTotal Total transaction value
   * @param trTax Transaction tax
   * @param trShipping Transaction shipping cost
   * @param tiCurrency Initial transaction item currency
   * @param tiPrice Initial transaction item price
   * @param collectorTstamp Collector timestamp
   * @return Validation[Tuple] containing all input amounts converted to the base currency
   */
  def convertCurrencies(
    trCurrency: Option[String],
    trTotal: Option[Double],
    trTax: Option[Double],
    trShipping: Option[Double],
    tiCurrency: Option[String],
    tiPrice: Option[Double],
    collectorTstamp: Option[DateTime]
  ): ValidationNel[String, (Option[String], Option[String], Option[String], Option[String])] =
    collectorTstamp match {
      case Some(tstamp) =>
        try {
          val newCurrencyTr = performConversion(trCurrency, trTotal, tstamp)
          val newCurrencyTi = performConversion(tiCurrency, tiPrice, tstamp)
          val newTrTax = performConversion(trCurrency, trTax, tstamp)
          val newTrShipping = performConversion(trCurrency, trShipping, tstamp)
          (newCurrencyTr.toValidationNel |@| newTrTax.toValidationNel |@| newTrShipping.toValidationNel |@| newCurrencyTi.toValidationNel) {
            (_, _, _, _)
          }
        } catch {
          case e: NoSuchElementException =>
            "Base currency [%s] not supported: [%s]".format(baseCurrency, e).failNel
          case f: UnknownHostException =>
            "Could not connect to Open Exchange Rates: [%s]".format(f).failNel
          case NonFatal(g) => "Unexpected exception converting currency: [%s]".format(g).failNel
        }
      case None => "Collector timestamp missing".failNel // This should never happen
    }
}
