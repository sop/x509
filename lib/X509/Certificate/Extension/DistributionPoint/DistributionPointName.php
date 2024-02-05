<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\X501\ASN1\RDN;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Base class for *DistributionPointName* ASN.1 CHOICE type used by
 * 'CRL Distribution Points' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
abstract class DistributionPointName
{
    public const TAG_FULL_NAME = 0;
    public const TAG_RDN = 1;

    /**
     * Type.
     *
     * @var int
     */
    protected $_tag;

    /**
     * Initialize from TaggedType.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromTaggedType(TaggedType $el): self
    {
        switch ($el->tag()) {
            case self::TAG_FULL_NAME:
                return new FullName(
                    GeneralNames::fromASN1(
                        $el->asImplicit(Element::TYPE_SEQUENCE)->asSequence()));
            case self::TAG_RDN:
                return new RelativeName(
                    RDN::fromASN1($el->asImplicit(Element::TYPE_SET)->asSet()));
            default:
                throw new \UnexpectedValueException(
                    'DistributionPointName tag ' . $el->tag() . ' not supported.');
        }
    }

    /**
     * Get type tag.
     */
    public function tag(): int
    {
        return $this->_tag;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): ImplicitlyTaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, $this->_valueASN1());
    }

    /**
     * Generate ASN.1 element.
     */
    abstract protected function _valueASN1(): Element;
}
