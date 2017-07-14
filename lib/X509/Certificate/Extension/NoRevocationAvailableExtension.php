<?php

namespace X509\Certificate\Extension;

use ASN1\Type\Primitive\NullType;

/**
 * Implements 'No Revocation Available' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.6
 */
class NoRevocationAvailableExtension extends Extension
{
    /**
     * Constructor.
     *
     * @param bool $critical
     */
    public function __construct($critical)
    {
        parent::__construct(self::OID_NO_REV_AVAIL, $critical);
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER($data, $critical)
    {
        NullType::fromDER($data);
        return new self($critical);
    }
    
    /**
     *
     * {@inheritdoc}
     * @return NullType
     */
    protected function _valueASN1()
    {
        return new NullType();
    }
}
