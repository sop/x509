<?php

declare(strict_types = 1);

namespace X509\GeneralName;

use ASN1\Type\TaggedType;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * Implements <i>ediPartyName</i> CHOICE type of <i>GeneralName</i>.
 *
 * Currently acts as a parking object for decoding.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 * @todo Implement EDIPartyName type
 */
class EDIPartyName extends GeneralName
{
    /**
     *
     * @var \ASN1\Element
     */
    protected $_element;
    
    /**
     * Constructor.
     */
    protected function __construct()
    {
        $this->_tag = self::TAG_EDI_PARTY_NAME;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): self
    {
        $obj = new self();
        $obj->_element = $el->asSequence();
        return $obj;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function string(): string
    {
        return bin2hex($this->_element->toDER());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, $this->_element);
    }
}
