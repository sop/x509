<?php

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;


/**
 * Implements 'Extended Key Usage' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.12
 */
class ExtendedKeyUsageExtension extends Extension implements \Countable, 
	\IteratorAggregate
{
	const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
	const OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
	const OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
	const OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
	const OID_IPSEC_END_SYSTEM = "1.3.6.1.5.5.7.3.5";
	const OID_IPSEC_TUNNEL = "1.3.6.1.5.5.7.3.6";
	const OID_IPSEC_USER = "1.3.6.1.5.5.7.3.7";
	const OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
	const OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
	const OID_DVCS = "1.3.6.1.5.5.7.3.10";
	const OID_SBGP_CERT_AA_SERVER_AUTH = "1.3.6.1.5.5.7.3.11";
	const OID_SCVP_RESPONDER = "1.3.6.1.5.5.7.3.12";
	const OID_EAP_OVER_PPP = "1.3.6.1.5.5.7.3.13";
	const OID_EAP_OVER_LAN = "1.3.6.1.5.5.7.3.14";
	const OID_SCVP_SERVER = "1.3.6.1.5.5.7.3.15";
	const OID_SCVP_CLIENT = "1.3.6.1.5.5.7.3.16";
	const OID_IPSEC_IKE = "1.3.6.1.5.5.7.3.17";
	const OID_CAPWAP_AC = "1.3.6.1.5.5.7.3.18";
	const OID_CAPWAP_WTP = "1.3.6.1.5.5.7.3.19";
	const OID_SIP_DOMAIN = "1.3.6.1.5.5.7.3.20";
	const OID_SECURE_SHELL_CLIENT = "1.3.6.1.5.5.7.3.21";
	const OID_SECURE_SHELL_SERVER = "1.3.6.1.5.5.7.3.22";
	const OID_SEND_ROUTER = "1.3.6.1.5.5.7.3.23";
	const OID_SEND_PROXY = "1.3.6.1.5.5.7.3.24";
	const OID_SEND_OWNER = "1.3.6.1.5.5.7.3.25";
	const OID_SEND_PROXIED_OWNER = "1.3.6.1.5.5.7.3.26";
	const OID_CMC_CA = "1.3.6.1.5.5.7.3.27";
	const OID_CMC_RA = "1.3.6.1.5.5.7.3.28";
	const OID_CMC_ARCHIVE = "1.3.6.1.5.5.7.3.29";
	
	/**
	 * Purpose OID's.
	 *
	 * @var string[] $_purposes
	 */
	protected $_purposes;
	
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param string ...$purposes
	 */
	public function __construct($critical, ...$purposes) {
		parent::__construct(self::OID_EXT_KEY_USAGE, $critical);
		$this->_purposes = $purposes;
	}
	
	protected static function _fromDER($data, $critical) {
		$purposes = array_map(
			function (Element $el) {
				return $el->expectType(Element::TYPE_OBJECT_IDENTIFIER)->oid();
			}, Sequence::fromDER($data)->elements());
		return new self($critical, ...$purposes);
	}
	
	/**
	 * Whether purposes are present.
	 *
	 * If multiple purposes are checked, all must be present.
	 *
	 * @param string ...$oids
	 * @return bool
	 */
	public function has(...$oids) {
		foreach ($oids as $oid) {
			if (!in_array($oid, $this->_purposes)) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Get key usage purpose OID's.
	 *
	 * @return string[]
	 */
	public function purposes() {
		return $this->_purposes;
	}
	
	protected function _valueASN1() {
		$elements = array_map(
			function ($oid) {
				return new ObjectIdentifier($oid);
			}, $this->_purposes);
		return new Sequence(...$elements);
	}
	
	/**
	 * Get the number of purposes.
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_purposes);
	}
	
	/**
	 * Get iterator for usage purposes.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_purposes);
	}
}
