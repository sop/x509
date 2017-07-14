<?php

namespace X509\Certificate\Extension;

use ASN1\Type\Primitive\OctetString;

/**
 * Implements 'Subject Key Identifier' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.2
 */
class SubjectKeyIdentifierExtension extends Extension
{
    /**
     * Key identifier.
     *
     * @var string $_keyIdentifier
     */
    protected $_keyIdentifier;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param string $keyIdentifier
     */
    public function __construct($critical, $keyIdentifier)
    {
        parent::__construct(self::OID_SUBJECT_KEY_IDENTIFIER, $critical);
        $this->_keyIdentifier = $keyIdentifier;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER($data, $critical)
    {
        return new self($critical, OctetString::fromDER($data)->string());
    }
    
    /**
     * Get key identifier.
     *
     * @return string
     */
    public function keyIdentifier()
    {
        return $this->_keyIdentifier;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return OctetString
     */
    protected function _valueASN1()
    {
        return new OctetString($this->_keyIdentifier);
    }
}
