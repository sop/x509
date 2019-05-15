<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate\Attribute;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *IetfAttrSyntax.values* ASN.1 CHOICE type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4
 */
class IetfAttrValue
{
    /**
     * Element type tag.
     *
     * @var int
     */
    protected $_type;

    /**
     * Value.
     *
     * @var string
     */
    protected $_value;

    /**
     * Constructor.
     *
     * @param string $value
     * @param int    $type
     */
    public function __construct(string $value, int $type)
    {
        $this->_type = $type;
        $this->_value = $value;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->_value;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param UnspecifiedType $el
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): self
    {
        switch ($el->tag()) {
            case Element::TYPE_OCTET_STRING:
            case Element::TYPE_UTF8_STRING:
                return new self($el->asString()->string(), $el->tag());
            case Element::TYPE_OBJECT_IDENTIFIER:
                return new self($el->asObjectIdentifier()->oid(), $el->tag());
        }
        throw new \UnexpectedValueException(
            'Type ' . Element::tagToName($el->tag()) . ' not supported.');
    }

    /**
     * Initialize from octet string.
     *
     * @param string $octets
     *
     * @return self
     */
    public static function fromOctets(string $octets): self
    {
        return new self($octets, Element::TYPE_OCTET_STRING);
    }

    /**
     * Initialize from UTF-8 string.
     *
     * @param string $str
     *
     * @return self
     */
    public static function fromString(string $str): self
    {
        return new self($str, Element::TYPE_UTF8_STRING);
    }

    /**
     * Initialize from OID.
     *
     * @param string $oid
     *
     * @return self
     */
    public static function fromOID(string $oid): self
    {
        return new self($oid, Element::TYPE_OBJECT_IDENTIFIER);
    }

    /**
     * Get type tag.
     *
     * @return int
     */
    public function type(): int
    {
        return $this->_type;
    }

    /**
     * Whether value type is octets.
     *
     * @return bool
     */
    public function isOctets(): bool
    {
        return Element::TYPE_OCTET_STRING === $this->_type;
    }

    /**
     * Whether value type is OID.
     *
     * @return bool
     */
    public function isOID(): bool
    {
        return Element::TYPE_OBJECT_IDENTIFIER === $this->_type;
    }

    /**
     * Whether value type is string.
     *
     * @return bool
     */
    public function isString(): bool
    {
        return Element::TYPE_UTF8_STRING === $this->_type;
    }

    /**
     * Get value.
     *
     * @return string
     */
    public function value(): string
    {
        return $this->_value;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @throws \LogicException
     *
     * @return Element
     */
    public function toASN1(): Element
    {
        switch ($this->_type) {
            case Element::TYPE_OCTET_STRING:
                return new OctetString($this->_value);
            case Element::TYPE_UTF8_STRING:
                return new UTF8String($this->_value);
            case Element::TYPE_OBJECT_IDENTIFIER:
                return new ObjectIdentifier($this->_value);
        }
        throw new \LogicException(
            'Type ' . Element::tagToName($this->_type) . ' not supported.');
    }
}
