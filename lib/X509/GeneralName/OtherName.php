<?php

namespace X509\GeneralName;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;


/**
 * Implements <i>otherName</i> CHOICE type of <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class OtherName extends GeneralName
{
	/**
	 * Type OID.
	 *
	 * @var string $_type
	 */
	protected $_type;
	
	/**
	 * Value.
	 *
	 * @var Element $_element
	 */
	protected $_element;
	
	/**
	 * Constructor
	 *
	 * @param string $type_id OID
	 * @param Element $el
	 */
	public function __construct($type_id, Element $el) {
		$this->_tag = self::TAG_OTHER_NAME;
		$this->_type = $type_id;
		$this->_element = $el;
	}
	
	/**
	 * Initialize from ASN.1
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	protected static function _fromASN1(Sequence $seq) {
		$type_id = $seq->at(0)
			->asObjectIdentifier()
			->oid();
		$value = $seq->getTagged(0)
			->asExplicit()
			->asElement();
		return new self($type_id, $value);
	}
	
	public function string() {
		return $this->_type . "/#" . bin2hex($this->_element->toDER());
	}
	
	/**
	 * Get type OID.
	 *
	 * @return string
	 */
	public function type() {
		return $this->_type;
	}
	
	/**
	 * Get value element.
	 *
	 * @return Element
	 */
	public function value() {
		return $this->_element;
	}
	
	protected function _choiceASN1() {
		return new ImplicitlyTaggedType($this->_tag, 
			new Sequence(new ObjectIdentifier($this->_type), 
				new ExplicitlyTaggedType(0, $this->_element)));
	}
}
