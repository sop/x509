<?php

namespace X509\Feature;


/**
 * Helper trait for classes employing date and time handling.
 */
trait DateTimeHelper
{
	/**
	 * Create DateTime object from time string and timezone.
	 *
	 * @param string|null $time Time string, default to 'now'
	 * @param string|null $tz Timezone, default if omitted
	 * @throws \RuntimeException
	 * @return \DateTimeImmutable
	 */
	private static function _createDateTime($time = null, $tz = null) {
		try {
			if (!isset($tz)) {
				$tz = date_default_timezone_get();
			}
			return new \DateTimeImmutable($time, self::_createTimeZone($tz));
		} catch (\Exception $e) {
			throw new \RuntimeException(
				"Failed to create DateTime: " .
					 self::_getLastDateTimeImmutableErrorsStr(), 0, $e);
		}
	}
	
	/**
	 * Create DateTimeZone object from string.
	 *
	 * @param string $tz
	 * @throws \UnexpectedValueException
	 * @return \DateTimeZone
	 */
	private static function _createTimeZone($tz) {
		try {
			return new \DateTimeZone($tz);
		} catch (\Exception $e) {
			throw new \UnexpectedValueException("Invalid timezone.", 0, $e);
		}
	}
	
	/**
	 * Get last error caused by DateTimeImmutable.
	 *
	 * @return string
	 */
	private static function _getLastDateTimeImmutableErrorsStr() {
		$errors = \DateTimeImmutable::getLastErrors()["errors"];
		return implode(", ", $errors);
	}
}
