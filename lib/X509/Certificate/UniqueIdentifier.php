<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\ASN1\Type\Primitive\BitString;

/**
 * Implements <i>UniqueIdentifier</i> ASN.1 type.
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
     *
     * @param BitString $bs
     */
    public function __construct(BitString $bs)
    {
        $this->_uid = $bs;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param BitString $bs
     *
     * @return self
     */
    public static function fromASN1(BitString $bs): UniqueIdentifier
    {
        return new self($bs);
    }

    /**
     * Initialize from string.
     *
     * @param string $str
     *
     * @return self
     */
    public static function fromString(string $str): UniqueIdentifier
    {
        return new self(new BitString($str));
    }

    /**
     * Get unique identifier as a string.
     *
     * @return string
     */
    public function string(): string
    {
        return $this->_uid->string();
    }

    /**
     * Get unique identifier as a bit string.
     *
     * @return BitString
     */
    public function bitString(): BitString
    {
        return $this->_uid;
    }

    /**
     * Get ASN.1 element.
     *
     * @return BitString
     */
    public function toASN1(): BitString
    {
        return $this->_uid;
    }
}
