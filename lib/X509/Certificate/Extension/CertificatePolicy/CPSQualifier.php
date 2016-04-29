<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Type\Primitive\IA5String;
use ASN1\Type\StringType;


/**
 * Implements <i>CPSuri</i> ASN.1 type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class CPSQualifier extends PolicyQualifierInfo
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
		$this->_oid = self::OID_CPS;
		$this->_uri = $uri;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param StringType $str
	 * @return self
	 */
	protected static function _fromASN1(StringType $str) {
		return new self($str->str());
	}
	
	/**
	 * Get URI.
	 *
	 * @return string
	 */
	public function uri() {
		return $this->_uri;
	}
	
	protected function _qualifierASN1() {
		return new IA5String($this->_uri);
	}
}
