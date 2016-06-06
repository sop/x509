<?php

namespace X509\GeneralName;

use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\UnspecifiedType;


/**
 * Implements <i>x400Address</i> CHOICE type of <i>GeneralName</i>.
 *
 * Currently acts as a parking object for decoding.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 * @todo Implement ORAddress type
 */
class X400Address extends GeneralName
{
	protected $_element;
	
	protected function __construct() {
		$this->_tag = self::TAG_X400_ADDRESS;
	}
	
	/**
	 *
	 * @param UnspecifiedType $el
	 * @return self
	 */
	public static function fromChosenASN1(UnspecifiedType $el) {
		$obj = new self();
		$obj->_element = $el->asSequence();
		return $obj;
	}
	
	public function string() {
		return bin2hex($this->_element->toDER());
	}
	
	protected function _choiceASN1() {
		return new ImplicitlyTaggedType($this->_tag, $this->_element);
	}
}
