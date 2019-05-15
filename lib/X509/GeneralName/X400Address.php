<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *x400Address* CHOICE type of *GeneralName*.
 *
 * Currently acts as a parking object for decoding.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 *
 * @todo Implement ORAddress type
 */
class X400Address extends GeneralName
{
    /**
     * @var \Sop\ASN1\Element
     */
    protected $_element;

    /**
     * Constructor.
     */
    protected function __construct()
    {
        $this->_tag = self::TAG_X400_ADDRESS;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        $obj = new self();
        $obj->_element = $el->asSequence();
        return $obj;
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return bin2hex($this->_element->toDER());
    }

    /**
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, $this->_element);
    }
}
