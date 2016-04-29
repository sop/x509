<?php

namespace X509\GeneralName;

use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Tagged\ImplicitlyTaggedType;


/**
 * Implements <i>registeredID</i> CHOICE type of <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class RegisteredID extends GeneralName
{
	/**
	 * Object identifier.
	 *
	 * @var string $_oid
	 */
	protected $_oid;
	
	/**
	 * Constructor
	 *
	 * @param string $oid OID in dotted format
	 */
	public function __construct($oid) {
		$this->_tag = self::TAG_REGISTERED_ID;
		$this->_oid = $oid;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param ObjectIdentifier $oid
	 * @return self
	 */
	protected static function _fromASN1(ObjectIdentifier $oid) {
		return new self($oid->oid());
	}
	
	public function string() {
		return $this->_oid;
	}
	
	/**
	 * Get object identifier in dotted format.
	 *
	 * @return string OID
	 */
	public function oid() {
		return $this->_oid;
	}
	
	protected function _choiceASN1() {
		return new ImplicitlyTaggedType($this->_tag, 
			new ObjectIdentifier($this->_oid));
	}
}
