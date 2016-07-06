<?php

namespace X509\AttributeCertificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\Certificate\Certificate;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralName;
use X509\GeneralName\GeneralNames;


/**
 * Implements <i>Holder</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 */
class Holder
{
	/**
	 * Holder PKC's issuer and serial.
	 *
	 * @var IssuerSerial|null $_baseCertificateID
	 */
	protected $_baseCertificateID;
	
	/**
	 * Holder PKC's subject.
	 *
	 * @var GeneralNames|null $_entityName
	 */
	protected $_entityName;
	
	/**
	 * Linked object.
	 *
	 * @var ObjectDigestInfo|null $_objectDigestInfo
	 */
	protected $_objectDigestInfo;
	
	/**
	 * Constructor
	 *
	 * @param IssuerSerial|null $issuer_serial
	 * @param GeneralNames|null $entity_name
	 */
	public function __construct(IssuerSerial $issuer_serial = null, 
			GeneralNames $entity_name = null) {
		$this->_baseCertificateID = $issuer_serial;
		$this->_entityName = $entity_name;
	}
	
	/**
	 * Initialize from a holder's public key certificate.
	 *
	 * @param Certificate $cert
	 * @return self
	 */
	public static function fromPKC(Certificate $cert) {
		return new self(IssuerSerial::fromPKC($cert));
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 */
	public static function fromASN1(Sequence $seq) {
		$cert_id = null;
		$entity_name = null;
		$digest_info = null;
		if ($seq->hasTagged(0)) {
			$cert_id = IssuerSerial::fromASN1(
				$seq->getTagged(0)
					->asImplicit(Element::TYPE_SEQUENCE)
					->asSequence());
		}
		if ($seq->hasTagged(1)) {
			$entity_name = GeneralNames::fromASN1(
				$seq->getTagged(1)
					->asImplicit(Element::TYPE_SEQUENCE)
					->asSequence());
		}
		if ($seq->hasTagged(2)) {
			$digest_info = ObjectDigestInfo::fromASN1(
				$seq->getTagged(2)
					->asImplicit(Element::TYPE_SEQUENCE)
					->asSequence());
		}
		$obj = new self($cert_id, $entity_name);
		$obj->_objectDigestInfo = $digest_info;
		return $obj;
	}
	
	/**
	 * Get self with base certificate ID.
	 *
	 * @param IssuerSerial $issuer
	 * @return self
	 */
	public function withBaseCertificateID(IssuerSerial $issuer) {
		$obj = clone $this;
		$obj->_baseCertificateID = $issuer;
		return $obj;
	}
	
	/**
	 * Get self with entity name.
	 *
	 * @param GeneralNames $names
	 * @return self
	 */
	public function withEntityName(GeneralNames $names) {
		$obj = clone $this;
		$obj->_entityName = $names;
		return $obj;
	}
	
	/**
	 * Get self with object digest info.
	 *
	 * @param ObjectDigestInfo $odi
	 * @return self
	 */
	public function withObjectDigestInfo(ObjectDigestInfo $odi) {
		$obj = clone $this;
		$obj->_objectDigestInfo = $odi;
		return $obj;
	}
	
	/**
	 * Check whether base certificate ID is present.
	 *
	 * @return bool
	 */
	public function hasBaseCertificateID() {
		return isset($this->_baseCertificateID);
	}
	
	/**
	 * Get base certificate ID.
	 *
	 * @throws \LogicException
	 * @return IssuerSerial
	 */
	public function baseCertificateID() {
		if (!$this->hasBaseCertificateID()) {
			throw new \LogicException("baseCertificateID not set.");
		}
		return $this->_baseCertificateID;
	}
	
	/**
	 * Check whether entity name is present.
	 *
	 * @return bool
	 */
	public function hasEntityName() {
		return isset($this->_entityName);
	}
	
	/**
	 * Get entity name
	 *
	 * @throws \LogicException
	 * @return GeneralNames
	 */
	public function entityName() {
		if (!$this->hasEntityName()) {
			throw new \LogicException("entityName not set.");
		}
		return $this->_entityName;
	}
	
	/**
	 * Check whether object digest info is present.
	 *
	 * @return bool
	 */
	public function hasObjectDigestInfo() {
		return isset($this->_objectDigestInfo);
	}
	
	/**
	 * Get object digest info
	 *
	 * @throws \LogicException
	 * @return ObjectDigestInfo
	 */
	public function objectDigestInfo() {
		if (!$this->hasObjectDigestInfo()) {
			throw new \LogicException("objectDigestInfo not set.");
		}
		return $this->_objectDigestInfo;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array();
		if (isset($this->_baseCertificateID)) {
			$elements[] = new ImplicitlyTaggedType(0, 
				$this->_baseCertificateID->toASN1());
		}
		if (isset($this->_entityName)) {
			$elements[] = new ImplicitlyTaggedType(1, 
				$this->_entityName->toASN1());
		}
		if (isset($this->_objectDigestInfo)) {
			$elements[] = new ImplicitlyTaggedType(2, 
				$this->_objectDigestInfo->toASN1());
		}
		return new Sequence(...$elements);
	}
	
	/**
	 * Check whether Holder identifies given certificate.
	 *
	 * @param Certificate $cert
	 * @return boolean
	 */
	public function identifiesPKC(Certificate $cert) {
		// if neither baseCertificateID nor entityName are present
		if (!$this->_baseCertificateID && !$this->_entityName) {
			return false;
		}
		// if baseCertificateID is present, but doesn't match
		if ($this->_baseCertificateID &&
			 !$this->_baseCertificateID->identifiesPKC($cert)) {
			return false;
		}
		// if entityName is present, but doesn't match
		if ($this->_entityName && !$this->_checkEntityName($cert)) {
			return false;
		}
		return true;
	}
	
	/**
	 * Check whether entityName matches the given certificate.
	 *
	 * @param Certificate $cert
	 * @return boolean
	 */
	private function _checkEntityName(Certificate $cert) {
		$name = $this->_entityName->firstDN();
		if ($cert->tbsCertificate()
			->subject()
			->equals($name)) {
			return true;
		}
		$exts = $cert->tbsCertificate()->extensions();
		if ($exts->hasSubjectAlternativeName()) {
			$ext = $exts->subjectAlternativeName();
			if ($this->_checkEntityAlternativeNames($ext->names())) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Check whether any of the subject alternative names match entityName.
	 *
	 * @param GeneralNames $san
	 * @return boolean
	 */
	private function _checkEntityAlternativeNames(GeneralNames $san) {
		// only directory names supported for now
		$name = $this->_entityName->firstDN();
		foreach ($san->allOf(GeneralName::TAG_DIRECTORY_NAME) as $dn) {
			if ($dn instanceof DirectoryName && $dn->dn()->equals($name)) {
				return true;
			}
		}
		return false;
	}
}
