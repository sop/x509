<?php

namespace X509\CertificationRequest;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\Crypto\Signature;
use CryptoUtil\PEM\PEM;


/**
 * Implements <i>CertificationRequest</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2986#section-4
 */
class CertificationRequest
{
	/**
	 * Certification request info.
	 *
	 * @var CertificationRequestInfo $_certificationRequestInfo
	 */
	protected $_certificationRequestInfo;
	
	/**
	 * Signature algorithm.
	 *
	 * @var AlgorithmIdentifierType $_signatureAlgorithm
	 */
	protected $_signatureAlgorithm;
	
	/**
	 * Signature.
	 *
	 * @var Signature $_signature
	 */
	protected $_signature;
	
	/**
	 * Constructor
	 *
	 * @param CertificationRequestInfo $info
	 * @param AlgorithmIdentifierType $algo
	 * @param Signature $signature
	 */
	public function __construct(CertificationRequestInfo $info, 
			AlgorithmIdentifierType $algo, Signature $signature) {
		$this->_certificationRequestInfo = $info;
		$this->_signatureAlgorithm = $algo;
		$this->_signature = $signature;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$info = CertificationRequestInfo::fromASN1(
			$seq->at(0, Element::TYPE_SEQUENCE));
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at(1, Element::TYPE_SEQUENCE));
		$signature = Signature::fromASN1($seq->at(2, Element::TYPE_BIT_STRING));
		return new self($info, $algo, $signature);
	}
	
	/**
	 * Initialize from DER.
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromDER($data) {
		return self::fromASN1(Sequence::fromDER($data));
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() !== PEM::TYPE_CERTIFICATE_REQUEST) {
			throw new \UnexpectedValueException("Invalid PEM type.");
		}
		return self::fromDER($pem->data());
	}
	
	/**
	 * Get certification request info.
	 *
	 * @return CertificationRequestInfo
	 */
	public function certificationRequestInfo() {
		return $this->_certificationRequestInfo;
	}
	
	/**
	 * Get signature algorithm.
	 *
	 * @return AlgorithmIdentifierType
	 */
	public function signatureAlgorithm() {
		return $this->_signatureAlgorithm;
	}
	
	/**
	 * Get signature.
	 *
	 * @return Signature
	 */
	public function signature() {
		return $this->_signature;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_certificationRequestInfo->toASN1(), 
			$this->_signatureAlgorithm->toASN1(), 
			$this->_signature->toBitString());
	}
	
	/**
	 * Get certification request as a DER.
	 *
	 * @return string
	 */
	public function toDER() {
		return $this->toASN1()->toDER();
	}
	
	/**
	 * Get certification request as a PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_CERTIFICATE_REQUEST, $this->toDER());
	}
	
	/**
	 * Verify certification request signature.
	 *
	 * @param Crypto $crypto
	 * @return bool True if signature matches
	 */
	public function verify(Crypto $crypto) {
		$data = $this->_certificationRequestInfo->toASN1()->toDER();
		$pk_info = $this->_certificationRequestInfo->subjectPKInfo();
		return $crypto->verify($data, $this->_signature, $pk_info, 
			$this->_signatureAlgorithm);
	}
	
	/**
	 * Get certification request as a PEM formatted string.
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->toPEM()->string();
	}
}
