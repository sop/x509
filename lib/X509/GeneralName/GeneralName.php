<?php

declare(strict_types=1);

namespace X509\GeneralName;

use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\UnspecifiedType;

/**
 * Implements <i>GeneralName</i> CHOICE with implicit tagging.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
abstract class GeneralName
{
    // GeneralName CHOICE tags
    const TAG_OTHER_NAME = 0;
    const TAG_RFC822_NAME = 1;
    const TAG_DNS_NAME = 2;
    const TAG_X400_ADDRESS = 3;
    const TAG_DIRECTORY_NAME = 4;
    const TAG_EDI_PARTY_NAME = 5;
    const TAG_URI = 6;
    const TAG_IP_ADDRESS = 7;
    const TAG_REGISTERED_ID = 8;
    
    /**
     * Chosen tag.
     *
     * @var int $_tag
     */
    protected $_tag;
    
    /**
     * Get string value of the type.
     *
     * @return string
     */
    abstract public function string();
    
    /**
     * Get ASN.1 value in GeneralName CHOICE context.
     *
     * @return TaggedType
     */
    abstract protected function _choiceASN1();
    
    /**
     * Initialize concrete object from the chosen ASN.1 element.
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el)
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . " must be implemented in the derived class.");
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param TaggedType $el
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(TaggedType $el)
    {
        switch ($el->tag()) {
            // otherName
            case self::TAG_OTHER_NAME:
                return OtherName::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_SEQUENCE));
            // rfc822Name
            case self::TAG_RFC822_NAME:
                return RFC822Name::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_IA5_STRING));
            // dNSName
            case self::TAG_DNS_NAME:
                return DNSName::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_IA5_STRING));
            // x400Address
            case self::TAG_X400_ADDRESS:
                return X400Address::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_SEQUENCE));
            // directoryName
            case self::TAG_DIRECTORY_NAME:
                // because Name is a CHOICE, albeit having only one option,
                // explicit tagging must be used
                // (see X.680 07/2002 30.6.c)
                return DirectoryName::fromChosenASN1($el->asExplicit());
            // ediPartyName
            case self::TAG_EDI_PARTY_NAME:
                return EDIPartyName::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_SEQUENCE));
            // uniformResourceIdentifier
            case self::TAG_URI:
                return UniformResourceIdentifier::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_IA5_STRING));
            // iPAddress
            case self::TAG_IP_ADDRESS:
                return IPAddress::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_OCTET_STRING));
            // registeredID
            case self::TAG_REGISTERED_ID:
                return RegisteredID::fromChosenASN1(
                    $el->asImplicit(Element::TYPE_OBJECT_IDENTIFIER));
        }
        throw new \UnexpectedValueException(
            "GeneralName type " . $el->tag() . " not supported.");
    }
    
    /**
     * Get type tag.
     *
     * @return int
     */
    public function tag()
    {
        return $this->_tag;
    }
    
    /**
     * Generate ASN.1 element.
     *
     * @return Element
     */
    public function toASN1()
    {
        return $this->_choiceASN1();
    }
    
    /**
     * Check whether GeneralName is equal to other.
     *
     * @param GeneralName $other GeneralName to compare to
     * @return boolean True if names are equal
     */
    public function equals(GeneralName $other)
    {
        if ($this->_tag != $other->_tag) {
            return false;
        }
        if ($this->_choiceASN1()->toDER() != $other->_choiceASN1()->toDER()) {
            return false;
        }
        return true;
    }
    
    /**
     * Get general name as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->string();
    }
}
