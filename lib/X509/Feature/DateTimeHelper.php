<?php

declare(strict_types = 1);

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
    private static function _createDateTime($time = null, $tz = null): \DateTimeImmutable
    {
        if (!isset($time)) {
            $time = 'now';
        }
        if (!isset($tz)) {
            $tz = date_default_timezone_get();
        }
        try {
            $dt = new \DateTimeImmutable($time, self::_createTimeZone($tz));
            return self::_roundDownFractionalSeconds($dt);
        } catch (\Exception $e) {
            throw new \RuntimeException(
                "Failed to create DateTime: " .
                     self::_getLastDateTimeImmutableErrorsStr(), 0, $e);
        }
    }
    
    /**
     * Rounds a \DateTimeImmutable value such that fractional
     * seconds are removed.
     *
     * @param \DateTimeImmutable $dt
     * @return \DateTimeImmutable
     */
    private static function _roundDownFractionalSeconds(\DateTimeImmutable $dt): \DateTimeImmutable
    {
        return \DateTimeImmutable::createFromFormat("Y-m-d H:i:s",
            $dt->format("Y-m-d H:i:s"), $dt->getTimezone());
    }
    
    /**
     * Create DateTimeZone object from string.
     *
     * @param string $tz
     * @throws \UnexpectedValueException
     * @return \DateTimeZone
     */
    private static function _createTimeZone(string $tz): \DateTimeZone
    {
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
    private static function _getLastDateTimeImmutableErrorsStr(): string
    {
        $errors = \DateTimeImmutable::getLastErrors()["errors"];
        return implode(", ", $errors);
    }
}
