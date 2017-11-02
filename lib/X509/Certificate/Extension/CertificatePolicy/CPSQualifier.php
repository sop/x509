<?php

declare(strict_types=1);

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\IA5String;

/**
 * Implements <i>CPSuri</i> ASN.1 type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class CPSQualifier extends PolicyQualifierInfo
{
    /**
     * URI.
     *
     * @var string $_uri
     */
    protected $_uri;
    
    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct(string $uri)
    {
        $this->_oid = self::OID_CPS;
        $this->_uri = $uri;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromQualifierASN1(UnspecifiedType $el)
    {
        return new self($el->asString()->string());
    }
    
    /**
     * Get URI.
     *
     * @return string
     */
    public function uri(): string
    {
        return $this->_uri;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return IA5String
     */
    protected function _qualifierASN1(): IA5String
    {
        return new IA5String($this->_uri);
    }
}
