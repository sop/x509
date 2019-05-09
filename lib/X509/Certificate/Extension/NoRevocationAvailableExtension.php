<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;

/**
 * Implements 'No Revocation Available' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.6
 */
class NoRevocationAvailableExtension extends Extension
{
    /**
     * Constructor.
     *
     * @param bool $critical
     */
    public function __construct(bool $critical)
    {
        parent::__construct(self::OID_NO_REV_AVAIL, $critical);
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        NullType::fromDER($data);
        return new self($critical);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        return new NullType();
    }
}
