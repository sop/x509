<?php

namespace X509\AttributeCertificate\Attribute;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X501\ASN1\AttributeType;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\BinaryMatch;
use X509\GeneralName\GeneralName;
use X509\GeneralName\GeneralNames;


/**
 * Implements value for 'Role' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.5
 */
class RoleAttributeValue extends AttributeValue
{
	/**
	 * Issuing authority.
	 *
	 * @var GeneralNames $_roleAuthority
	 */
	protected $_roleAuthority;
	
	/**
	 * Role name.
	 *
	 * @var GeneralName $_roleName
	 */
	protected $_roleName;
	
	/**
	 * Constructor
	 *
	 * @param GeneralName $name Role name
	 * @param GeneralNames $authority Issuing authority
	 */
	public function __construct(GeneralName $name, 
			GeneralNames $authority = null) {
		$this->_roleAuthority = $authority;
		$this->_roleName = $name;
		$this->_oid = AttributeType::OID_ROLE;
	}
	
	public static function fromASN1(Element $el) {
		$el->expectType(Element::TYPE_SEQUENCE);
		$authority = null;
		if ($el->hasTagged(0)) {
			$authority = GeneralNames::fromASN1(
				$el->getTagged(0)->implicit(Element::TYPE_SEQUENCE));
		}
		$name = GeneralName::fromASN1($el->getTagged(1)->explicit());
		return new self($name, $authority);
	}
	
	/**
	 * Check whether issuing authority is present.
	 *
	 * @return bool
	 */
	public function hasRoleAuthority() {
		return isset($this->_roleAuthority);
	}
	
	/**
	 * Get issuing authority.
	 *
	 * @throws \LogicException
	 * @return GeneralNames
	 */
	public function roleAuthority() {
		if (!$this->hasRoleAuthority()) {
			throw new \LogicException("roleAuthority not set.");
		}
		return $this->_roleAuthority;
	}
	
	/**
	 * Get role name.
	 *
	 * @return GeneralName
	 */
	public function roleName() {
		return $this->_roleName;
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::toASN1()
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array();
		if (isset($this->_roleAuthority)) {
			$elements[] = new ImplicitlyTaggedType(0, 
				$this->_roleAuthority->toASN1());
		}
		$elements[] = new ExplicitlyTaggedType(1, $this->_roleName->toASN1());
		return new Sequence(...$elements);
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::stringValue()
	 * @return string
	 */
	public function stringValue() {
		return "#" . bin2hex($this->toASN1()->toDER());
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::equalityMatchingRule()
	 * @return BinaryMatch
	 */
	public function equalityMatchingRule() {
		return new BinaryMatch();
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::rfc2253String()
	 * @return string
	 */
	public function rfc2253String() {
		return $this->stringValue();
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::_transcodedString()
	 * @return string
	 */
	protected function _transcodedString() {
		return $this->stringValue();
	}
}
