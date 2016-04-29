<?php

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralNames;


/**
 * Implements 'Authority Key Identifier' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.1
 */
class AuthorityKeyIdentifierExtension extends Extension
{
	/**
	 * Key identifier.
	 *
	 * @var string $_keyIdentifier
	 */
	protected $_keyIdentifier;
	
	/**
	 * Issuer name.
	 *
	 * @var GeneralNames $_authorityCertIssuer
	 */
	protected $_authorityCertIssuer;
	
	/**
	 * Issuer serial number.
	 *
	 * @var int|string $_authorityCertSerialNumber
	 */
	protected $_authorityCertSerialNumber;
	
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param string $keyIdentifier
	 * @param GeneralNames $issuer
	 * @param int|string $serial
	 */
	public function __construct($critical, $keyIdentifier, 
			GeneralNames $issuer = null, $serial = null) {
		parent::__construct(self::OID_AUTHORITY_KEY_IDENTIFIER, $critical);
		$this->_keyIdentifier = $keyIdentifier;
		$this->_authorityCertIssuer = $issuer;
		$this->_authorityCertSerialNumber = $serial;
	}
	
	protected static function _fromDER($data, $critical) {
		$seq = Sequence::fromDER($data);
		$keyIdentifier = null;
		$issuer = null;
		$serial = null;
		if ($seq->hasTagged(0)) {
			$keyIdentifier = $seq->getTagged(0)
				->implicit(Element::TYPE_OCTET_STRING)
				->str();
		}
		if ($seq->hasTagged(1) || $seq->hasTagged(2)) {
			if (!$seq->hasTagged(1) || !$seq->hasTagged(2)) {
				throw new \UnexpectedValueException(
					"AuthorityKeyIdentifier must have both" .
						 " authorityCertIssuer and authorityCertSerialNumber" .
						 " present or both absent");
			}
			$issuer = GeneralNames::fromASN1(
				$seq->getTagged(1)->implicit(Element::TYPE_SEQUENCE));
			$serial = $seq->getTagged(2)
				->implicit(Element::TYPE_INTEGER)
				->number();
		}
		return new self($critical, $keyIdentifier, $issuer, $serial);
	}
	
	/**
	 * Whether key identifier is present.
	 *
	 * @return bool
	 */
	public function hasKeyIdentifier() {
		return isset($this->_keyIdentifier);
	}
	
	/**
	 * Get key identifier.
	 *
	 * @throws \LogicException
	 * @return string
	 */
	public function keyIdentifier() {
		if (!$this->hasKeyIdentifier()) {
			throw new \LogicException("Key identifier not set");
		}
		return $this->_keyIdentifier;
	}
	
	/**
	 * Whether issuer is present.
	 *
	 * @return bool
	 */
	public function hasIssuer() {
		return isset($this->_authorityCertIssuer);
	}
	
	/**
	 * Get issuer.
	 *
	 * @throws \LogicException
	 * @return GeneralNames
	 */
	public function issuer() {
		if (!$this->hasIssuer()) {
			throw new \LogicException("Issuer not set");
		}
		return $this->_authorityCertIssuer;
	}
	
	/**
	 * Get serial number.
	 *
	 * @throws \LogicException
	 * @return int|string
	 */
	public function serial() {
		// both issuer and serial must be present or both absent
		if (!$this->hasIssuer()) {
			throw new \LogicException("Issuer not set");
		}
		return $this->_authorityCertSerialNumber;
	}
	
	protected function _valueASN1() {
		$elements = array();
		if (isset($this->_keyIdentifier)) {
			$elements[] = new ImplicitlyTaggedType(0, 
				new OctetString($this->_keyIdentifier));
		}
		if (isset($this->_authorityCertIssuer)) {
			$elements[] = new ImplicitlyTaggedType(1, 
				$this->_authorityCertIssuer->toASN1());
		}
		if (isset($this->_authorityCertSerialNumber)) {
			$elements[] = new ImplicitlyTaggedType(2, 
				new Integer($this->_authorityCertSerialNumber));
		}
		return new Sequence(...$elements);
	}
}
