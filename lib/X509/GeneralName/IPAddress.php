<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements <i>iPAddress</i> CHOICE type of <i>GeneralName</i>.
 *
 * Concrete classes <code>IPv4Address</code> and <code>IPv6Address</code>
 * furthermore implement the parsing semantics.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
abstract class IPAddress extends GeneralName
{
    /**
     * IP address.
     *
     * @var string
     */
    protected $_ip;

    /**
     * Subnet mask.
     *
     * @var null|string
     */
    protected $_mask;

    /**
     * Constructor.
     *
     * @param string      $ip
     * @param null|string $mask
     */
    public function __construct(string $ip, ?string $mask = null)
    {
        $this->_tag = self::TAG_IP_ADDRESS;
        $this->_ip = $ip;
        $this->_mask = $mask;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        $octets = $el->asOctetString()->string();
        switch (strlen($octets)) {
            case 4:
            case 8:
                return IPv4Address::fromOctets($octets);
            case 16:
            case 32:
                return IPv6Address::fromOctets($octets);
            default:
                throw new \UnexpectedValueException(
                    'Invalid octet length for IP address.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_ip . (isset($this->_mask) ? '/' . $this->_mask : '');
    }

    /**
     * Get IP address as a string.
     *
     * @return string
     */
    public function address(): string
    {
        return $this->_ip;
    }

    /**
     * Check whether mask is present.
     *
     * @return bool
     */
    public function hasMask(): bool
    {
        return isset($this->_mask);
    }

    /**
     * Get subnet mask as a string.
     *
     * @throws \LogicException If not set
     *
     * @return string
     */
    public function mask(): string
    {
        if (!$this->hasMask()) {
            throw new \LogicException('mask is not set.');
        }
        return $this->_mask;
    }

    /**
     * Get octet representation of the IP address.
     *
     * @return string
     */
    abstract protected function _octets(): string;

    /**
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag,
            new OctetString($this->_octets()));
    }
}
