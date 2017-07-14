<?php

namespace X509\Certificate;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use X509\CertificationPath\CertificationPath;

/**
 * Ordered list of certificates from the end-entity to the trust anchor.
 */
class CertificateChain implements \Countable, \IteratorAggregate
{
    /**
     * List of certificates in a chain.
     *
     * @var Certificate[]
     */
    protected $_certs;
    
    /**
     * Constructor.
     *
     * @param Certificate ...$certs List of certificates, end-entity first
     */
    public function __construct(Certificate ...$certs)
    {
        $this->_certs = $certs;
    }
    
    /**
     * Initialize from a list of PEMs.
     *
     * @param PEM ...$pems
     * @return self
     */
    public static function fromPEMs(PEM ...$pems)
    {
        $certs = array_map(
            function (PEM $pem) {
                return Certificate::fromPEM($pem);
            }, $pems);
        return new self(...$certs);
    }
    
    /**
     * Initialize from a string containing multiple PEM blocks.
     *
     * @param string $str
     * @return self
     */
    public static function fromPEMString($str)
    {
        $pems = PEMBundle::fromString($str)->all();
        return self::fromPEMs(...$pems);
    }
    
    /**
     * Get all certificates in a chain ordered from the end-entity certificate
     * to the trust anchor.
     *
     * @return Certificate[]
     */
    public function certificates()
    {
        return $this->_certs;
    }
    
    /**
     * Get the end-entity certificate.
     *
     * @throws \LogicException
     * @return Certificate
     */
    public function endEntityCertificate()
    {
        if (!count($this->_certs)) {
            throw new \LogicException("No certificates.");
        }
        return $this->_certs[0];
    }
    
    /**
     * Get the trust anchor certificate.
     *
     * @throws \LogicException
     * @return Certificate
     */
    public function trustAnchorCertificate()
    {
        if (!count($this->_certs)) {
            throw new \LogicException("No certificates.");
        }
        return $this->_certs[count($this->_certs) - 1];
    }
    
    /**
     * Convert certificate chain to certification path.
     *
     * @return CertificationPath
     */
    public function certificationPath()
    {
        return CertificationPath::fromCertificateChain($this);
    }
    
    /**
     * Convert certificate chain to string of PEM blocks.
     *
     * @return string
     */
    public function toPEMString()
    {
        return implode("\n",
            array_map(
                function (Certificate $cert) {
                    return $cert->toPEM()->string();
                }, $this->_certs));
    }
    
    /**
     *
     * @see \Countable::count()
     * @return int
     */
    public function count()
    {
        return count($this->_certs);
    }
    
    /**
     * Get iterator for certificates.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->_certs);
    }
}
