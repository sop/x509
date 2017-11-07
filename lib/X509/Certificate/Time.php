<?php

declare(strict_types = 1);

namespace X509\Certificate;

use ASN1\Element;
use ASN1\Type\TimeType;
use ASN1\Type\Primitive\GeneralizedTime;
use ASN1\Type\Primitive\UTCTime;
use X509\Feature\DateTimeHelper;

/**
 * Implements <i>Time</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1
 */
class Time
{
    use DateTimeHelper;
    
    /**
     * Datetime.
     *
     * @var \DateTimeImmutable $_dt
     */
    protected $_dt;
    
    /**
     * Time ASN.1 type tag.
     *
     * @var int $_type
     */
    protected $_type;
    
    /**
     * Constructor.
     *
     * @param \DateTimeImmutable $dt
     */
    public function __construct(\DateTimeImmutable $dt)
    {
        $this->_dt = $dt;
        $this->_type = self::_determineType($dt);
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param TimeType $el
     * @return self
     */
    public static function fromASN1(TimeType $el): self
    {
        $obj = new self($el->dateTime());
        $obj->_type = $el->tag();
        return $obj;
    }
    
    /**
     * Initialize from date string.
     *
     * @param string|null $time
     * @param string|null $tz
     * @return self
     */
    public static function fromString($time, $tz = null): self
    {
        return new self(self::_createDateTime($time, $tz));
    }
    
    /**
     * Get datetime.
     *
     * @return \DateTimeImmutable
     */
    public function dateTime(): \DateTimeImmutable
    {
        return $this->_dt;
    }
    
    /**
     * Generate ASN.1.
     *
     * @throws \UnexpectedValueException
     * @return TimeType
     */
    public function toASN1(): TimeType
    {
        $dt = $this->_dt;
        switch ($this->_type) {
            case Element::TYPE_UTC_TIME:
                return new UTCTime($dt);
            case Element::TYPE_GENERALIZED_TIME:
                // GeneralizedTime must not contain fractional seconds
                // (rfc5280 4.1.2.5.2)
                if ($dt->format("u") != 0) {
                    // remove fractional seconds (round down)
                    $dt = self::_roundDownFractionalSeconds($dt);
                }
                return new GeneralizedTime($dt);
        }
        throw new \UnexpectedValueException(
            "Time type " . Element::tagToName($this->_type) . " not supported.");
    }
    
    /**
     * Determine whether to use UTCTime or GeneralizedTime ASN.1 type.
     *
     * @param \DateTimeImmutable $dt
     * @return int Type tag
     */
    protected static function _determineType(\DateTimeImmutable $dt): int
    {
        if ($dt->format("Y") >= 2050) {
            return Element::TYPE_GENERALIZED_TIME;
        }
        return Element::TYPE_UTC_TIME;
    }
}
