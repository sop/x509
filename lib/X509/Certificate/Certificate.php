<?php

namespace X509\Certificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\Crypto\Signature;
use CryptoUtil\PEM\PEM;
use X509\Certificate\TBSCertificate;


/**
 * Implements <i>Certificate</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1
 */
class Certificate
{
	/**
	 * "To be signed" certificate information.
	 *
	 * @var TBSCertificate $_tbsCertificate
	 */
	protected $_tbsCertificate;
	
	/**
	 * Signature algorithm.
	 *
	 * @var AlgorithmIdentifier $_signatureAlgorithm
	 */
	protected $_signatureAlgorithm;
	
	/**
	 * Signature value.
	 *
	 * @var Signature $_signatureValue
	 */
	protected $_signatureValue;
	
	/**
	 * Constructor
	 *
	 * @param TBSCertificate $tbsCert
	 * @param AlgorithmIdentifier $algo
	 * @param Signature $signature
	 */
	public function __construct(TBSCertificate $tbsCert, 
			AlgorithmIdentifier $algo, Signature $signature) {
		$this->_tbsCertificate = $tbsCert;
		$this->_signatureAlgorithm = $algo;
		$this->_signatureValue = $signature;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$tbsCert = TBSCertificate::fromASN1($seq->at(0, Element::TYPE_SEQUENCE));
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at(1, Element::TYPE_SEQUENCE));
		$signature = Signature::fromASN1($seq->at(2, Element::TYPE_BIT_STRING));
		return new self($tbsCert, $algo, $signature);
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
		if ($pem->type() != PEM::TYPE_CERTIFICATE) {
			throw new \UnexpectedValueException("Invalid PEM type.");
		}
		return self::fromDER($pem->data());
	}
	
	/**
	 * Get certificate information.
	 *
	 * @return TBSCertificate
	 */
	public function tbsCertificate() {
		return $this->_tbsCertificate;
	}
	
	/**
	 * Get signature algorithm.
	 *
	 * @return AlgorithmIdentifier
	 */
	public function signatureAlgorithm() {
		return $this->_signatureAlgorithm;
	}
	
	/**
	 * Get signature value.
	 *
	 * @return Signature
	 */
	public function signatureValue() {
		return $this->_signatureValue;
	}
	
	/**
	 * Whether certificate is self-issued.
	 *
	 * @return bool
	 */
	public function isSelfIssued() {
		return $this->_tbsCertificate->subject()->equals(
			$this->_tbsCertificate->issuer());
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_tbsCertificate->toASN1(), 
			$this->_signatureAlgorithm->toASN1(), 
			$this->_signatureValue->toBitString());
	}
	
	/**
	 * Get certificate as a DER.
	 *
	 * @return string
	 */
	public function toDER() {
		return $this->toASN1()->toDER();
	}
	
	/**
	 * Get certificate as a PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_CERTIFICATE, $this->toDER());
	}
	
	/**
	 * Verify certificate signature.
	 *
	 * @param Crypto $crypto
	 * @param PublicKeyInfo $pubkey_info Issuer's public key
	 * @return bool True if certificate signature is valid
	 */
	public function verify(Crypto $crypto, PublicKeyInfo $pubkey_info) {
		$data = $this->_tbsCertificate->toASN1()->toDER();
		return $crypto->verify($data, $this->_signatureValue, $pubkey_info, 
			$this->_signatureAlgorithm);
	}
	
	/**
	 * Get certificate as a PEM formatted string.
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->toPEM()->str();
	}
}
