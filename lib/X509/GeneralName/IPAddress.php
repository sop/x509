<?php

namespace X509\GeneralName;

use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Tagged\ImplicitlyTaggedType;


/**
 * Implements <i>iPAddress</i> CHOICE type of <i>GeneralName</i>.
 *
 * Concrete classes <code>IPv4Address</code> and <code>IPv6Address</code>
 * furthermore implement the parsing semantics.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
abstract class IPAddress extends GeneralName
{
	/**
	 * IP address.
	 *
	 * @var string $_ip
	 */
	protected $_ip;
	
	/**
	 * Subnet mask.
	 *
	 * @var string|null $_mask
	 */
	protected $_mask;
	
	/**
	 * Get octet representation of the IP address.
	 *
	 * @return string
	 */
	abstract protected function _octets();
	
	/**
	 * Constructor
	 *
	 * @param string $ip
	 * @param string|null $mask
	 */
	public function __construct($ip, $mask = null) {
		$this->_tag = self::TAG_IP_ADDRESS;
		$this->_ip = $ip;
		$this->_mask = $mask;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param OctetString $str
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	protected static function _fromASN1(OctetString $str) {
		$octets = $str->str();
		switch (strlen($octets)) {
		case 4:
		case 8:
			return IPv4Address::fromOctets($octets);
		case 16:
		case 32:
			return IPv6Address::fromOctets($octets);
		default:
			throw new \UnexpectedValueException(
				"Invalid octet length for IP address.");
		}
	}
	
	public function string() {
		return $this->_ip . (isset($this->_mask) ? "/" . $this->_mask : "");
	}
	
	/**
	 * Get IP address as a string.
	 *
	 * @return string
	 */
	public function address() {
		return $this->_ip;
	}
	
	/**
	 * Get subnet mask as a string.
	 *
	 * @return string
	 */
	public function mask() {
		return $this->_mask;
	}
	
	protected function _choiceASN1() {
		return new ImplicitlyTaggedType($this->_tag, 
			new OctetString($this->_octets()));
	}
}
