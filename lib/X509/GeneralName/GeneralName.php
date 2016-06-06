<?php

namespace X509\GeneralName;

use ASN1\Element;
use ASN1\Type\TaggedType;


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
	 * Initialize from ASN.1.
	 *
	 * @param TaggedType $el
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(TaggedType $el) {
		switch ($el->tag()) {
		// otherName
		case self::TAG_OTHER_NAME:
			return OtherName::_fromASN1(
				$el->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
		// rfc822Name
		case self::TAG_RFC822_NAME:
			return RFC822Name::_fromASN1(
				$el->asImplicit(Element::TYPE_IA5_STRING)->asIA5String());
		// dNSName
		case self::TAG_DNS_NAME:
			return DNSName::_fromASN1(
				$el->asImplicit(Element::TYPE_IA5_STRING)->asIA5String());
		// x400Address
		case self::TAG_X400_ADDRESS:
			return X400Address::_fromASN1(
				$el->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
		// directoryName
		case self::TAG_DIRECTORY_NAME:
			// because Name is a CHOICE, albeit having only one option,
			// explicit tagging must be used
			// (see X.680 07/2002 30.6.c)
			return DirectoryName::_fromASN1($el->asExplicit()->asSequence());
		// ediPartyName
		case self::TAG_EDI_PARTY_NAME:
			return EDIPartyName::_fromASN1(
				$el->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
		// uniformResourceIdentifier
		case self::TAG_URI:
			return UniformResourceIdentifier::_fromASN1(
				$el->asImplicit(Element::TYPE_IA5_STRING)->asIA5String());
		// iPAddress
		case self::TAG_IP_ADDRESS:
			return IPAddress::_fromASN1(
				$el->asImplicit(Element::TYPE_OCTET_STRING)->asOctetString());
		// registeredID
		case self::TAG_REGISTERED_ID:
			return RegisteredID::_fromASN1(
				$el->asImplicit(Element::TYPE_OBJECT_IDENTIFIER)->asObjectIdentifier());
		}
		throw new \UnexpectedValueException(
			"GeneralName type " . $el->tag() . " not supported.");
	}
	
	/**
	 * Get type tag.
	 *
	 * @return int
	 */
	public function tag() {
		return $this->_tag;
	}
	
	/**
	 * Generate ASN.1 element.
	 *
	 * @return Element
	 */
	public function toASN1() {
		return $this->_choiceASN1();
	}
	
	/**
	 * Get general name as a string.
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->string();
	}
}
