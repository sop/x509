<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Sop\X509\CertificationPath\CertificationPath;

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
     */
    public static function fromPEMs(PEM ...$pems): self
    {
        $certs = array_map(
            function (PEM $pem) {
                return Certificate::fromPEM($pem);
            }, $pems);
        return new self(...$certs);
    }

    /**
     * Initialize from a string containing multiple PEM blocks.
     */
    public static function fromPEMString(string $str): self
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
    public function certificates(): array
    {
        return $this->_certs;
    }

    /**
     * Get the end-entity certificate.
     *
     * @throws \LogicException
     */
    public function endEntityCertificate(): Certificate
    {
        if (!count($this->_certs)) {
            throw new \LogicException('No certificates.');
        }
        return $this->_certs[0];
    }

    /**
     * Get the trust anchor certificate.
     *
     * @throws \LogicException
     */
    public function trustAnchorCertificate(): Certificate
    {
        if (!count($this->_certs)) {
            throw new \LogicException('No certificates.');
        }
        return $this->_certs[count($this->_certs) - 1];
    }

    /**
     * Convert certificate chain to certification path.
     */
    public function certificationPath(): CertificationPath
    {
        return CertificationPath::fromCertificateChain($this);
    }

    /**
     * Convert certificate chain to string of PEM blocks.
     */
    public function toPEMString(): string
    {
        return implode("\n",
            array_map(
                function (Certificate $cert) {
                    return $cert->toPEM()->string();
                }, $this->_certs));
    }

    /**
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_certs);
    }

    /**
     * Get iterator for certificates.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_certs);
    }
}
