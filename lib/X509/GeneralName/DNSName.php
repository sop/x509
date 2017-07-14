<?php

namespace X509\GeneralName;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\IA5String;
use ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * Implements <i>dNSName</i> CHOICE type of <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class DNSName extends GeneralName
{
    /**
     * DNS name.
     *
     * @var string
     */
    protected $_name;
    
    /**
     * Constructor.
     *
     * @param string $name Domain name
     */
    public function __construct($name)
    {
        $this->_tag = self::TAG_DNS_NAME;
        $this->_name = $name;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el)
    {
        return new self($el->asIA5String()->string());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function string()
    {
        return $this->_name;
    }
    
    /**
     * Get DNS name.
     *
     * @return string
     */
    public function name()
    {
        return $this->_name;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _choiceASN1()
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_name));
    }
}
