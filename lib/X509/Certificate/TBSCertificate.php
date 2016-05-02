<?php

namespace X509\Certificate;

use ASN1\DERData;
use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use X509\CertificationRequest\CertificationRequest;


/**
 * Implements <i>TBSCertificate</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1.2
 */
class TBSCertificate
{
	// Certificate version enumerations
	const VERSION_1 = 0;
	const VERSION_2 = 1;
	const VERSION_3 = 2;
	
	/**
	 * Certificate version.
	 *
	 * @var int
	 */
	protected $_version;
	
	/**
	 * Serial number.
	 *
	 * @var int
	 */
	protected $_serialNumber;
	
	/**
	 * Signature algorithm.
	 *
	 * @var AlgorithmIdentifier
	 */
	protected $_signature;
	
	/**
	 * Certificate issuer.
	 *
	 * @var Name $_issuer
	 */
	protected $_issuer;
	
	/**
	 * Certificate validity period.
	 *
	 * @var Validity $_validity
	 */
	protected $_validity;
	
	/**
	 * Certificate subject.
	 *
	 * @var Name $_subject
	 */
	protected $_subject;
	
	/**
	 * Subject public key.
	 *
	 * @var PublicKeyInfo $_subjectPublicKeyInfo
	 */
	protected $_subjectPublicKeyInfo;
	
	/**
	 * Issuer unique identifier.
	 *
	 * @var UniqueIdentifier|null $_issuerUniqueID
	 */
	protected $_issuerUniqueID;
	
	/**
	 * Subject unique identifier.
	 *
	 * @var UniqueIdentifier|null $_subjectUniqueID
	 */
	protected $_subjectUniqueID;
	
	/**
	 * Extensions.
	 *
	 * @var Extensions $_extensions
	 */
	protected $_extensions;
	
	/**
	 * Constructor
	 *
	 * @param Name $subject Certificate subject
	 * @param PublicKeyInfo $pki Subject public key
	 * @param Name $issuer Certificate issuer
	 * @param Validity $validity Validity period
	 */
	public function __construct(Name $subject, PublicKeyInfo $pki, Name $issuer, 
			Validity $validity) {
		$this->_subject = $subject;
		$this->_subjectPublicKeyInfo = $pki;
		$this->_issuer = $issuer;
		$this->_validity = $validity;
		$this->_extensions = new Extensions();
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$idx = 0;
		if ($seq->hasTagged(0)) {
			$idx++;
			$version = intval(
				$seq->getTagged(0)
					->explicit(Element::TYPE_INTEGER)
					->number());
		} else {
			$version = self::VERSION_1;
		}
		$serial = $seq->at($idx++, Element::TYPE_INTEGER)->number();
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at($idx++, Element::TYPE_SEQUENCE));
		$issuer = Name::fromASN1($seq->at($idx++, Element::TYPE_SEQUENCE));
		$validity = Validity::fromASN1($seq->at($idx++, Element::TYPE_SEQUENCE));
		$subject = Name::fromASN1($seq->at($idx++, Element::TYPE_SEQUENCE));
		$pki = PublicKeyInfo::fromASN1($seq->at($idx++, Element::TYPE_SEQUENCE));
		$tbs_cert = new self($subject, $pki, $issuer, $validity);
		$tbs_cert->_version = $version;
		$tbs_cert->_serialNumber = $serial;
		$tbs_cert->_signature = $algo;
		if ($seq->hasTagged(1)) {
			$tbs_cert->_issuerUniqueID = UniqueIdentifier::fromASN1(
				$seq->getTagged(1)->implicit(Element::TYPE_BIT_STRING));
		}
		if ($seq->hasTagged(2)) {
			$tbs_cert->_subjectUniqueID = UniqueIdentifier::fromASN1(
				$seq->getTagged(2)->implicit(Element::TYPE_BIT_STRING));
		}
		if ($seq->hasTagged(3)) {
			$tbs_cert->_extensions = Extensions::fromASN1(
				$seq->getTagged(3)->explicit(Element::TYPE_SEQUENCE));
		}
		return $tbs_cert;
	}
	
	/**
	 * Initialize from certification request.
	 *
	 * Note that signature is not verified and must be done by the caller.
	 *
	 * @param CertificationRequest $cr
	 * @return self
	 */
	public static function fromCSR(CertificationRequest $cr) {
		$cri = $cr->certificationRequestInfo();
		$tbs_cert = new self($cri->subject(), $cri->subjectPKInfo(), new Name(), 
			Validity::fromStrings(null, null));
		// if CSR has Extension Request attribute
		if ($cri->hasAttributes()) {
			$attribs = $cri->attributes();
			if ($attribs->hasExtensionRequest()) {
				$tbs_cert = $tbs_cert->withExtensions(
					$attribs->extensionRequest()
						->extensions());
			}
		}
		// add Subject Key Identifier extension
		$tbs_cert = $tbs_cert->withAdditionalExtensions(
			new SubjectKeyIdentifierExtension(false, 
				$cri->subjectPKInfo()
					->keyIdentifier()));
		return $tbs_cert;
	}
	
	/**
	 * Get self with fields set from the issuer's certificate.
	 *
	 * Issuer shall be set to issuing certificate's subject.
	 * Authority key identifier extensions shall be added with a key identifier
	 * set to issuing certificate's public key identifier.
	 *
	 * @param Certificate $cert Issuing party's certificate
	 * @return self
	 */
	public function withIssuerCertificate(Certificate $cert) {
		$obj = clone $this;
		// set issuer DN from cert's subject
		$obj->_issuer = $cert->tbsCertificate()->subject();
		// add authority key identifier extension
		$key_id = $cert->tbsCertificate()
			->subjectPublicKeyInfo()
			->keyIdentifier();
		$obj->_extensions = $obj->_extensions->withExtensions(
			new AuthorityKeyIdentifierExtension(true, $key_id));
		return $obj;
	}
	
	/**
	 * Get self with given version.
	 *
	 * If version is not set, appropriate version is automatically
	 * determined during signing.
	 *
	 * @param int $version
	 * @return self
	 */
	public function withVersion($version) {
		$obj = clone $this;
		$obj->_version = $version;
		return $obj;
	}
	
	/**
	 * Get self with given serial number.
	 *
	 * @param int|string $serial Base 10 number
	 * @return self
	 */
	public function withSerialNumber($serial) {
		$obj = clone $this;
		$obj->_serialNumber = $serial;
		return $obj;
	}
	
	/**
	 * Get self with given signature algorithm.
	 *
	 * @param SignatureAlgorithmIdentifier $algo
	 * @return self
	 */
	public function withSignature(SignatureAlgorithmIdentifier $algo) {
		$obj = clone $this;
		$obj->_signature = $algo;
		return $obj;
	}
	
	/**
	 * Get self with given issuer.
	 *
	 * @param Name $issuer
	 * @return self
	 */
	public function withIssuer(Name $issuer) {
		$obj = clone $this;
		$obj->_issuer = $issuer;
		return $obj;
	}
	
	/**
	 * Get self with given validity.
	 *
	 * @param Validity $validity
	 * @return self
	 */
	public function withValidity(Validity $validity) {
		$obj = clone $this;
		$obj->_validity = $validity;
		return $obj;
	}
	
	/**
	 * Get self with issuer unique ID.
	 *
	 * @param UniqueIdentifier $id
	 * @return self
	 */
	public function withIssuerUniqueID(UniqueIdentifier $id) {
		$obj = clone $this;
		$obj->_issuerUniqueID = $id;
		return $obj;
	}
	
	/**
	 * Get self with subject unique ID.
	 *
	 * @param UniqueIdentifier $id
	 * @return self
	 */
	public function withSubjectUniqueID(UniqueIdentifier $id) {
		$obj = clone $this;
		$obj->_subjectUniqueID = $id;
		return $obj;
	}
	
	/**
	 * Get self with given extensions.
	 *
	 * @param Extensions $extensions
	 * @return self
	 */
	public function withExtensions(Extensions $extensions) {
		$obj = clone $this;
		$obj->_extensions = $extensions;
		return $obj;
	}
	
	/**
	 * Get self with extensions added.
	 *
	 * @param Extension ...$exts One or more Extension objects
	 * @return self
	 */
	public function withAdditionalExtensions(Extension ...$exts) {
		$obj = clone $this;
		$obj->_extensions = $obj->_extensions->withExtensions(...$exts);
		return $obj;
	}
	
	/**
	 * Check whether version is set.
	 *
	 * @return bool
	 */
	public function hasVersion() {
		return isset($this->_version);
	}
	
	/**
	 * Get certificate version.
	 *
	 * @return int
	 */
	public function version() {
		if (!$this->hasVersion()) {
			throw new \LogicException("version not set");
		}
		return $this->_version;
	}
	
	/**
	 * Check whether serial number is set.
	 *
	 * @return bool
	 */
	public function hasSerialNumber() {
		return isset($this->_serialNumber);
	}
	
	/**
	 * Get serial number.
	 *
	 * @return int|string Base 10 integer
	 */
	public function serialNumber() {
		if (!$this->hasSerialNumber()) {
			throw new \LogicException("serialNumber not set");
		}
		return $this->_serialNumber;
	}
	
	/**
	 * Check whether signature algorithm is set.
	 *
	 * @return bool
	 */
	public function hasSignature() {
		return isset($this->_signature);
	}
	
	/**
	 * Get signature algorithm.
	 *
	 * @return AlgorithmIdentifier
	 */
	public function signature() {
		if (!$this->hasSignature()) {
			throw new \LogicException("signature not set");
		}
		return $this->_signature;
	}
	
	/**
	 * Get issuer.
	 *
	 * @return Name
	 */
	public function issuer() {
		return $this->_issuer;
	}
	
	/**
	 * Get validity period.
	 *
	 * @return Validity
	 */
	public function validity() {
		return $this->_validity;
	}
	
	/**
	 * Get subject.
	 *
	 * @return Name
	 */
	public function subject() {
		return $this->_subject;
	}
	
	/**
	 * Get subject public key.
	 *
	 * @return PublicKeyInfo
	 */
	public function subjectPublicKeyInfo() {
		return $this->_subjectPublicKeyInfo;
	}
	
	/**
	 * Whether issuer unique identifier is present.
	 *
	 * @return bool
	 */
	public function hasIssuerUniqueID() {
		return isset($this->_issuerUniqueID);
	}
	
	/**
	 * Get issuerUniqueID.
	 *
	 * @return UniqueIdentifier
	 */
	public function issuerUniqueID() {
		if (!$this->hasIssuerUniqueID()) {
			throw new \LogicException("issuerUniqueID not set");
		}
		return $this->_issuerUniqueID;
	}
	
	/**
	 * Whether subject unique identifier is present.
	 *
	 * @return bool
	 */
	public function hasSubjectUniqueID() {
		return isset($this->_subjectUniqueID);
	}
	
	/**
	 * Get subjectUniqueID.
	 *
	 * @return UniqueIdentifier
	 */
	public function subjectUniqueID() {
		if (!$this->hasSubjectUniqueID()) {
			throw new \LogicException("subjectUniqueID not set");
		}
		return $this->_subjectUniqueID;
	}
	
	/**
	 * Get extensions.
	 *
	 * @return Extensions
	 */
	public function extensions() {
		return $this->_extensions;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array();
		$version = $this->version();
		// if version is not default
		if ($version != self::VERSION_1) {
			$elements[] = new ExplicitlyTaggedType(0, new Integer($version));
		}
		$serial = $this->serialNumber();
		$signature = $this->signature();
		// add required elements
		array_push($elements, new Integer($serial), $signature->toASN1(), 
			$this->_issuer->toASN1(), $this->_validity->toASN1(), 
			$this->_subject->toASN1(), $this->_subjectPublicKeyInfo->toASN1());
		if (isset($this->_issuerUniqueID)) {
			$elements[] = new ImplicitlyTaggedType(1, 
				$this->_issuerUniqueID->toASN1());
		}
		if (isset($this->_subjectUniqueID)) {
			$elements[] = new ImplicitlyTaggedType(2, 
				$this->_subjectUniqueID->toASN1());
		}
		if (count($this->_extensions)) {
			$elements[] = new ExplicitlyTaggedType(3, 
				$this->_extensions->toASN1());
		}
		return new Sequence(...$elements);
	}
	
	/**
	 * Create signed certificate.
	 *
	 * @param Crypto $crypto Crypto engine
	 * @param SignatureAlgorithmIdentifier $algo Algorithm used for signing
	 * @param PrivateKeyInfo $privkey_info Private key used for signing
	 * @return PEM
	 */
	public function sign(Crypto $crypto, SignatureAlgorithmIdentifier $algo, 
			PrivateKeyInfo $privkey_info) {
		$tbsCert = clone $this;
		if (!isset($tbsCert->_version)) {
			$tbsCert->_version = $tbsCert->_determineVersion();
		}
		if (!isset($tbsCert->_serialNumber)) {
			$tbsCert->_serialNumber = 0;
		}
		$tbsCert->_signature = $algo;
		$data = $tbsCert->toASN1()->toDER();
		$signature = $crypto->sign($data, $privkey_info, $algo);
		$seq = new Sequence(new DERData($data), $algo->toASN1(), 
			$signature->toBitString());
		return new PEM(PEM::TYPE_CERTIFICATE, $seq->toDER());
	}
	
	/**
	 * Determine minimum version for the certificate.
	 *
	 * @return int
	 */
	protected function _determineVersion() {
		// if extensions are present
		if (count($this->_extensions)) {
			return self::VERSION_3;
		}
		// if UniqueIdentifier is present
		if (isset($this->_issuerUniqueID) || isset($this->_subjectUniqueID)) {
			return self::VERSION_2;
		}
		return self::VERSION_1;
	}
}
