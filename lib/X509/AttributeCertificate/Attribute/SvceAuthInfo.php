<?php

namespace X509\AttributeCertificate\Attribute;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\BinaryMatch;
use X509\GeneralName\GeneralName;


/**
 * Base class implementing <i>SvceAuthInfo</i> ASN.1 type used by
 * attribute certificate attribute values.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.1
 */
abstract class SvceAuthInfo extends AttributeValue
{
	/**
	 * Service.
	 *
	 * @var GeneralName $_service
	 */
	protected $_service;
	
	/**
	 * Ident.
	 *
	 * @var GeneralName $_ident
	 */
	protected $_ident;
	
	/**
	 * Auth info.
	 *
	 * @var string|null $_authInfo
	 */
	protected $_authInfo;
	
	/**
	 * Constructor
	 *
	 * @param GeneralName $service
	 * @param GeneralName $ident
	 * @param string|null $auth_info
	 */
	public function __construct(GeneralName $service, GeneralName $ident, 
			$auth_info = null) {
		$this->_service = $service;
		$this->_ident = $ident;
		$this->_authInfo = $auth_info;
	}
	
	public static function fromASN1(Element $el) {
		$el->expectType(Element::TYPE_SEQUENCE);
		$service = GeneralName::fromASN1($el->at(0));
		$ident = GeneralName::fromASN1($el->at(1));
		$auth_info = null;
		if ($el->has(2, Element::TYPE_OCTET_STRING)) {
			$auth_info = $el->at(2)->str();
		}
		return new static($service, $ident, $auth_info);
	}
	
	/**
	 * Get service name.
	 *
	 * @return GeneralName
	 */
	public function service() {
		return $this->_service;
	}
	
	/**
	 * Get ident.
	 *
	 * @return GeneralName
	 */
	public function ident() {
		return $this->_ident;
	}
	
	/**
	 * Check whether authentication info is present.
	 *
	 * @return bool
	 */
	public function hasAuthInfo() {
		return isset($this->_authInfo);
	}
	
	/**
	 * Get authentication info.
	 *
	 * @throws \LogicException
	 * @return string
	 */
	public function authInfo() {
		if (!$this->hasAuthInfo()) {
			throw new \LogicException("authInfo not set.");
		}
		return $this->_authInfo;
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::toASN1()
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array($this->_service->toASN1(), $this->_ident->toASN1());
		if (isset($this->_authInfo)) {
			$elements[] = new OctetString($this->_authInfo);
		}
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
