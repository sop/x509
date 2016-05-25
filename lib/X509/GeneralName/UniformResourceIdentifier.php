<?php

namespace X509\GeneralName;

use ASN1\Type\Primitive\IA5String;
use ASN1\Type\StringType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;


/**
 * Implements <i>uniformResourceIdentifier</i> CHOICE type of
 * <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class UniformResourceIdentifier extends GeneralName
{
	/**
	 * URI.
	 *
	 * @var string $_uri
	 */
	protected $_uri;
	
	/**
	 * Constructor
	 *
	 * @param string $uri
	 */
	public function __construct($uri) {
		$this->_tag = self::TAG_URI;
		$this->_uri = $uri;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param StringType $str
	 * @return self
	 */
	protected static function _fromASN1(StringType $str) {
		return new self($str->string());
	}
	
	public function string() {
		return $this->_uri;
	}
	
	/**
	 * Get URI.
	 *
	 * @return string
	 */
	public function uri() {
		return $this->_uri;
	}
	
	protected function _choiceASN1() {
		return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_uri));
	}
}
