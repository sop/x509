<?php

namespace X509\Certificate\Extension\Target;

use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\TaggedType;
use X509\GeneralName\GeneralName;


/**
 * Implements 'targetGroup' CHOICE of the <i>Target</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class TargetGroup extends Target
{
	/**
	 * Group name.
	 *
	 * @var GeneralName $_name
	 */
	protected $_name;
	
	/**
	 * Constructor
	 *
	 * @param GeneralName $name
	 */
	public function __construct(GeneralName $name) {
		$this->_name = $name;
		$this->_type = self::TYPE_GROUP;
	}
	
	protected static function _fromASN1(TaggedType $el) {
		return new self(GeneralName::fromASN1($el));
	}
	
	public function string() {
		return $this->_name->string();
	}
	
	/**
	 * Get group name.
	 *
	 * @return GeneralName
	 */
	public function name() {
		return $this->_name;
	}
	
	public function toASN1() {
		return new ExplicitlyTaggedType($this->_type, $this->_name->toASN1());
	}
}
