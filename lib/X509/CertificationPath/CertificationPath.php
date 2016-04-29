<?php

namespace X509\CertificationPath;

use CryptoUtil\Crypto\Crypto;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\Exception\PathValidationException;
use X509\CertificationPath\PathBuilding\CertificationPathBuilder;
use X509\CertificationPath\PathValidation\PathValidationConfig;
use X509\CertificationPath\PathValidation\PathValidationResult;
use X509\CertificationPath\PathValidation\PathValidator;


/**
 * Implements certification path structure.
 *
 * Certification path is a list of certificates from the trust anchor to
 * the end entity certificate, possibly spanning over multiple intermediate
 * certificates.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-3.2
 */
class CertificationPath implements \Countable, \IteratorAggregate
{
	/**
	 * Certification path.
	 *
	 * @var Certificate[] $_certificates
	 */
	protected $_certificates;
	
	/**
	 * Constructor
	 *
	 * @param Certificate ...$certificates Certificates from the trust anchor
	 *        to the target end-entity certificate
	 */
	public function __construct(Certificate ...$certificates) {
		$this->_certificates = $certificates;
	}
	
	/**
	 * Build certification path to given target.
	 *
	 * @param Certificate $target Target end-entity certificate
	 * @param CertificateBundle $trust_anchors List of trust anchors
	 * @param CertificateBundle|null $intermediate Optional intermediate
	 *        certificates
	 * @return self
	 */
	public static function toTarget(Certificate $target, 
			CertificateBundle $trust_anchors, 
			CertificateBundle $intermediate = null) {
		$builder = new CertificationPathBuilder($trust_anchors);
		return $builder->shortestPathToTarget($target, $intermediate);
	}
	
	/**
	 * Build certification path from given trust anchor to target certificate,
	 * using intermediate certificates from given bundle.
	 *
	 * @param Certificate $trust_anchor Trust anchor certificate
	 * @param Certificate $target Target end-entity certificate
	 * @param CertificateBundle|null $intermediate Optional intermediate
	 *        certificates
	 * @return self
	 */
	public static function fromTrustAnchorToTarget(Certificate $trust_anchor, 
			Certificate $target, CertificateBundle $intermediate = null) {
		return self::toTarget($target, new CertificateBundle($trust_anchor), 
			$intermediate);
	}
	
	/**
	 * Get certificates.
	 *
	 * @return Certificate[]
	 */
	public function certificates() {
		return $this->_certificates;
	}
	
	/**
	 * Validate certification path.
	 *
	 * @param Crypto $crypto
	 * @param PathValidationConfig $config
	 * @throws PathValidationException
	 * @return PathValidationResult
	 */
	public function validate(Crypto $crypto, PathValidationConfig $config) {
		$validator = new PathValidator($crypto, $config, ...$this->_certificates);
		return $validator->validate();
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_certificates);
	}
	
	/**
	 * Get iterator for certificates.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_certificates);
	}
}
