<?php

namespace X509\GeneralName;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\IA5String;
use ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * Implements <i>rfc822Name</i> CHOICE type of <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class RFC822Name extends GeneralName
{
    /**
     * Email.
     *
     * @var string $_email
     */
    protected $_email;
    
    /**
     * Constructor.
     *
     * @param string $email
     */
    public function __construct($email)
    {
        $this->_tag = self::TAG_RFC822_NAME;
        $this->_email = $email;
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
        return $this->_email;
    }
    
    /**
     * Get email.
     *
     * @return string
     */
    public function email()
    {
        return $this->_email;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _choiceASN1()
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_email));
    }
}
