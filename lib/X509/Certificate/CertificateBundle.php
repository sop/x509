<?php

namespace X509\Certificate;

use CryptoUtil\PEM\PEM;
use CryptoUtil\PEM\PEMBundle;


class CertificateBundle implements \Countable, \IteratorAggregate
{
	/**
	 * Certificates.
	 *
	 * @var Certificate[] $_certs
	 */
	protected $_certs;
	
	/**
	 * Constructor
	 *
	 * @param Certificate ...$certs Certificate objects
	 */
	public function __construct(Certificate ...$certs) {
		$this->_certs = $certs;
	}
	
	/**
	 * Initialize from PEM bundle.
	 *
	 * @param PEMBundle $pem_bundle
	 * @return self
	 */
	public static function fromPEMBundle(PEMBundle $pem_bundle) {
		$certs = array_map(
			function ($pem) {
				return Certificate::fromPEM($pem);
			}, $pem_bundle->all());
		return new self(...$certs);
	}
	
	/**
	 * Initialize from PEMs.
	 *
	 * @param PEM ...$pems PEM objects
	 * @return self
	 */
	public static function fromPEMs(PEM ...$pems) {
		$certs = array_map(
			function ($pem) {
				return Certificate::fromPEM($pem);
			}, $pems);
		return new self(...$certs);
	}
	
	/**
	 * Get self with certificates from PEMBundle added.
	 *
	 * @param PEMBundle $pem_bundle
	 * @return self
	 */
	public function withPEMBundle(PEMBundle $pem_bundle) {
		$certs = $this->_certs;
		foreach ($pem_bundle as $pem) {
			$certs[] = Certificate::fromPEM($pem);
		}
		return new self(...$certs);
	}
	
	/**
	 * Get self with single certificate from PEM added.
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public function withPEM(PEM $pem) {
		$certs = $this->_certs;
		$certs[] = Certificate::fromPEM($pem);
		return new self(...$certs);
	}
	
	/**
	 * Get all certificates that have given subject key identifier.
	 *
	 * @param string $id
	 * @return Certificate[]
	 */
	public function allBySubjectKeyIdentifier($id) {
		$certs = array();
		foreach ($this->_certs as $cert) {
			$extensions = $cert->tbsCertificate()->extensions();
			if (!$extensions->hasSubjectKeyIdentifier()) {
				continue;
			}
			if ($id === $extensions->subjectKeyIdentifier()->keyIdentifier()) {
				$certs[] = $cert;
			}
		}
		return $certs;
	}
	
	/**
	 * Get all certificates in a bundle.
	 *
	 * @return Certificate[]
	 */
	public function all() {
		return $this->_certs;
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_certs);
	}
	
	/**
	 * Get iterator for certificates.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_certs);
	}
}
