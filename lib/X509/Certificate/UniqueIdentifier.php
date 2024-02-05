<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\ASN1\Type\Primitive\BitString;

/**
 * Implements *UniqueIdentifier* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2.8
 */
class UniqueIdentifier
{
    /**
     * Identifier.
     *
     * @var BitString
     */
    protected $_uid;

    /**
     * Constructor.
     */
    public function __construct(BitString $bs)
    {
        $this->_uid = $bs;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(BitString $bs): UniqueIdentifier
    {
        return new self($bs);
    }

    /**
     * Initialize from string.
     */
    public static function fromString(string $str): UniqueIdentifier
    {
        return new self(new BitString($str));
    }

    /**
     * Get unique identifier as a string.
     */
    public function string(): string
    {
        return $this->_uid->string();
    }

    /**
     * Get unique identifier as a bit string.
     */
    public function bitString(): BitString
    {
        return $this->_uid;
    }

    /**
     * Get ASN.1 element.
     */
    public function toASN1(): BitString
    {
        return $this->_uid;
    }
}
