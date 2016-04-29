<?php

namespace X509\AttributeCertificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\Crypto\Signature;
use CryptoUtil\PEM\PEM;


/**
 * Implements <i>AttributeCertificate</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 */
class AttributeCertificate
{
	/**
	 * Attribute certificate info.
	 *
	 * @var AttributeCertificateInfo $_acinfo
	 */
	protected $_acinfo;
	
	/**
	 * Signature algorithm identifier.
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
	 * @param AttributeCertificateInfo $acinfo
	 * @param AlgorithmIdentifier $algo
	 * @param Signature $signature
	 */
	public function __construct(AttributeCertificateInfo $acinfo, 
			AlgorithmIdentifier $algo, Signature $signature) {
		$this->_acinfo = $acinfo;
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
		$acinfo = AttributeCertificateInfo::fromASN1(
			$seq->at(0, Element::TYPE_SEQUENCE));
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at(1, Element::TYPE_SEQUENCE));
		$signature = Signature::fromASN1($seq->at(2, Element::TYPE_BIT_STRING));
		return new self($acinfo, $algo, $signature);
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() !== PEM::TYPE_ATTRIBUTE_CERTIFICATE) {
			throw new \UnexpectedValueException("Invalid PEM type");
		}
		return self::fromASN1(Sequence::fromDER($pem->data()));
	}
	
	/**
	 * Get attribute certificate info.
	 *
	 * @return AttributeCertificateInfo
	 */
	public function acinfo() {
		return $this->_acinfo;
	}
	
	/**
	 * Get signature algorithm identifier.
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
	 * Get ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_acinfo->toASN1(), 
			$this->_signatureAlgorithm->toASN1(), 
			$this->_signatureValue->toBitString());
	}
	
	/**
	 * Get attribute certificate as a PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $this->toASN1()->toDER());
	}
	
	/**
	 * Verify signature.
	 *
	 * @param Crypto $crypto
	 * @param PublicKeyInfo $pubkey_info Signer's public key
	 * @return bool
	 */
	public function verify(Crypto $crypto, PublicKeyInfo $pubkey_info) {
		$data = $this->_acinfo->toASN1()->toDER();
		return $crypto->verify($data, $this->_signatureValue, $pubkey_info, 
			$this->_signatureAlgorithm);
	}
}
