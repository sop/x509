<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\CertificatePolicy;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *CPSuri* ASN.1 type used by 'Certificate Policies'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class CPSQualifier extends PolicyQualifierInfo
{
    /**
     * URI.
     *
     * @var string
     */
    protected $_uri;

    /**
     * Constructor.
     */
    public function __construct(string $uri)
    {
        $this->_oid = self::OID_CPS;
        $this->_uri = $uri;
    }

    /**
     * @return self
     */
    public static function fromQualifierASN1(UnspecifiedType $el): PolicyQualifierInfo
    {
        return new self($el->asString()->string());
    }

    /**
     * Get URI.
     */
    public function uri(): string
    {
        return $this->_uri;
    }

    protected function _qualifierASN1(): Element
    {
        return new IA5String($this->_uri);
    }
}
