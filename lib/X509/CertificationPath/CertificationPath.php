<?php

namespace X509\CertificationPath;

use Sop\CryptoBridge\Crypto;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\Certificate\CertificateChain;
use X509\CertificationPath\PathBuilding\CertificationPathBuilder;
use X509\CertificationPath\PathValidation\PathValidationConfig;
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
     * Constructor.
     *
     * @param Certificate ...$certificates Certificates from the trust anchor
     *        to the target end-entity certificate
     */
    public function __construct(Certificate ...$certificates)
    {
        $this->_certificates = $certificates;
    }
    
    /**
     * Initialize from a certificate chain.
     *
     * @param CertificateChain $chain
     * @return self
     */
    public static function fromCertificateChain(CertificateChain $chain)
    {
        return new self(...array_reverse($chain->certificates(), false));
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
        CertificateBundle $trust_anchors, CertificateBundle $intermediate = null)
    {
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
        Certificate $target, CertificateBundle $intermediate = null)
    {
        return self::toTarget($target, new CertificateBundle($trust_anchor),
            $intermediate);
    }
    
    /**
     * Get certificates.
     *
     * @return Certificate[]
     */
    public function certificates()
    {
        return $this->_certificates;
    }
    
    /**
     * Get the trust anchor certificate from the path.
     *
     * @throws \LogicException If path is empty
     * @return Certificate
     */
    public function trustAnchorCertificate()
    {
        if (!count($this->_certificates)) {
            throw new \LogicException("No certificates.");
        }
        return $this->_certificates[0];
    }
    
    /**
     * Get the end-entity certificate from the path.
     *
     * @throws \LogicException If path is empty
     * @return Certificate
     */
    public function endEntityCertificate()
    {
        if (!count($this->_certificates)) {
            throw new \LogicException("No certificates.");
        }
        return $this->_certificates[count($this->_certificates) - 1];
    }
    
    /**
     * Get certification path as a certificate chain.
     *
     * @return CertificateChain
     */
    public function certificateChain()
    {
        return new CertificateChain(
            ...array_reverse($this->_certificates, false));
    }
    
    /**
     * Check whether certification path starts with one ore more given
     * certificates in parameter order.
     *
     * @param Certificate ...$certs Certificates
     * @return true
     */
    public function startsWith(Certificate ...$certs)
    {
        $n = count($certs);
        if ($n > count($this->_certificates)) {
            return false;
        }
        for ($i = 0; $i < $n; ++$i) {
            if (!$certs[$i]->equals($this->_certificates[$i])) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Validate certification path.
     *
     * @param Crypto $crypto
     * @param PathValidationConfig $config
     * @throws Exception\PathValidationException
     * @return PathValidation\PathValidationResult
     */
    public function validate(Crypto $crypto, PathValidationConfig $config)
    {
        $validator = new PathValidator($crypto, $config, ...$this->_certificates);
        return $validator->validate();
    }
    
    /**
     *
     * @see \Countable::count()
     * @return int
     */
    public function count()
    {
        return count($this->_certificates);
    }
    
    /**
     * Get iterator for certificates.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->_certificates);
    }
}
