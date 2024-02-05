<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationPath;

use Sop\CryptoBridge\Crypto;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\Certificate\CertificateChain;
use Sop\X509\CertificationPath\PathBuilding\CertificationPathBuilder;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;
use Sop\X509\CertificationPath\PathValidation\PathValidator;

/**
 * Implements certification path structure.
 *
 * Certification path is a list of certificates from the trust anchor to
 * the end entity certificate, possibly spanning over multiple intermediate
 * certificates.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-3.2
 */
class CertificationPath implements \Countable, \IteratorAggregate
{
    /**
     * Certification path.
     *
     * @var Certificate[]
     */
    protected $_certificates;

    /**
     * Constructor.
     *
     * @param Certificate ...$certificates Certificates from the trust anchor
     *                                     to the target end-entity certificate
     */
    public function __construct(Certificate ...$certificates)
    {
        $this->_certificates = $certificates;
    }

    /**
     * Initialize from a certificate chain.
     */
    public static function fromCertificateChain(CertificateChain $chain): self
    {
        return new self(...array_reverse($chain->certificates(), false));
    }

    /**
     * Build certification path to given target.
     *
     * @param Certificate            $target        Target end-entity certificate
     * @param CertificateBundle      $trust_anchors List of trust anchors
     * @param null|CertificateBundle $intermediate  Optional intermediate certificates
     */
    public static function toTarget(Certificate $target,
        CertificateBundle $trust_anchors, ?CertificateBundle $intermediate = null): self
    {
        $builder = new CertificationPathBuilder($trust_anchors);
        return $builder->shortestPathToTarget($target, $intermediate);
    }

    /**
     * Build certification path from given trust anchor to target certificate,
     * using intermediate certificates from given bundle.
     *
     * @param Certificate            $trust_anchor Trust anchor certificate
     * @param Certificate            $target       Target end-entity certificate
     * @param null|CertificateBundle $intermediate Optional intermediate certificates
     */
    public static function fromTrustAnchorToTarget(Certificate $trust_anchor,
        Certificate $target, ?CertificateBundle $intermediate = null): self
    {
        return self::toTarget($target, new CertificateBundle($trust_anchor),
            $intermediate);
    }

    /**
     * Get certificates.
     *
     * @return Certificate[]
     */
    public function certificates(): array
    {
        return $this->_certificates;
    }

    /**
     * Get the trust anchor certificate from the path.
     *
     * @throws \LogicException If path is empty
     */
    public function trustAnchorCertificate(): Certificate
    {
        if (!count($this->_certificates)) {
            throw new \LogicException('No certificates.');
        }
        return $this->_certificates[0];
    }

    /**
     * Get the end-entity certificate from the path.
     *
     * @throws \LogicException If path is empty
     */
    public function endEntityCertificate(): Certificate
    {
        if (!count($this->_certificates)) {
            throw new \LogicException('No certificates.');
        }
        return $this->_certificates[count($this->_certificates) - 1];
    }

    /**
     * Get certification path as a certificate chain.
     */
    public function certificateChain(): CertificateChain
    {
        return new CertificateChain(...array_reverse($this->_certificates, false));
    }

    /**
     * Check whether certification path starts with one ore more given
     * certificates in parameter order.
     *
     * @param Certificate ...$certs Certificates
     */
    public function startsWith(Certificate ...$certs): bool
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
     * @param null|Crypto $crypto Crypto engine, use default if not set
     *
     * @throws Exception\PathValidationException
     */
    public function validate(PathValidationConfig $config,
        ?Crypto $crypto = null): PathValidationResult
    {
        $crypto = $crypto ?? Crypto::getDefault();
        $validator = new PathValidator($crypto, $config, ...$this->_certificates);
        return $validator->validate();
    }

    /**
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_certificates);
    }

    /**
     * Get iterator for certificates.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_certificates);
    }
}
