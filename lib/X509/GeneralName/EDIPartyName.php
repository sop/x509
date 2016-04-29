<?php

namespace X509\GeneralName;

use ASN1\Type\Constructed\Sequence;


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
	protected $_element;
	
	protected function __construct() {
		$this->_tag = self::TAG_EDI_PARTY_NAME;
	}
	
	protected static function _fromASN1(Sequence $seq) {
		$obj = new self();
		$obj->_element = $seq;
		return $obj;
	}
	
	public function string() {
		return bin2hex($this->_element->toDER());
	}
	
	protected function _choiceASN1() {
		return $this->_element;
	}
}
