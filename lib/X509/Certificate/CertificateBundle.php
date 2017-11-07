<?php

declare(strict_types = 1);

namespace X509\Certificate;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;

/**
 * Implements a list of certificates.
 */
class CertificateBundle implements \Countable, \IteratorAggregate
{
    /**
     * Certificates.
     *
     * @var Certificate[] $_certs
     */
    protected $_certs;
    
    /**
     * Mapping from public key id to array of certificates.
     *
     * @var null|(Certificate[])[]
     */
    private $_keyIdMap;
    
    /**
     * Constructor.
     *
     * @param Certificate[] $certs Certificate objects
     */
    public function __construct(Certificate ...$certs)
    {
        $this->_certs = $certs;
    }
    
    /**
     * Reset internal cached variables on clone.
     */
    public function __clone()
    {
        $this->_keyIdMap = null;
    }
    
    /**
     * Initialize from PEMs.
     *
     * @param PEM[] $pems PEM objects
     * @return self
     */
    public static function fromPEMs(PEM ...$pems): self
    {
        $certs = array_map(
            function ($pem) {
                return Certificate::fromPEM($pem);
            }, $pems);
        return new self(...$certs);
    }
    
    /**
     * Initialize from PEM bundle.
     *
     * @param PEMBundle $pem_bundle
     * @return self
     */
    public static function fromPEMBundle(PEMBundle $pem_bundle): self
    {
        return self::fromPEMs(...$pem_bundle->all());
    }
    
    /**
     * Get self with certificates added.
     *
     * @param Certificate[] $cert
     * @return self
     */
    public function withCertificates(Certificate ...$cert): self
    {
        $obj = clone $this;
        $obj->_certs = array_merge($obj->_certs, $cert);
        return $obj;
    }
    
    /**
     * Get self with certificates from PEMBundle added.
     *
     * @param PEMBundle $pem_bundle
     * @return self
     */
    public function withPEMBundle(PEMBundle $pem_bundle): self
    {
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
    public function withPEM(PEM $pem): self
    {
        $certs = $this->_certs;
        $certs[] = Certificate::fromPEM($pem);
        return new self(...$certs);
    }
    
    /**
     * Check whether bundle contains a given certificate.
     *
     * @param Certificate $cert
     * @return bool
     */
    public function contains(Certificate $cert): bool
    {
        $id = self::_getCertKeyId($cert);
        $map = $this->_getKeyIdMap();
        if (!isset($map[$id])) {
            return false;
        }
        foreach ($map[$id] as $c) {
            /** @var Certificate $c */
            if ($cert->equals($c)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get all certificates that have given subject key identifier.
     *
     * @param string $id
     * @return Certificate[]
     */
    public function allBySubjectKeyIdentifier(string $id): array
    {
        $map = $this->_getKeyIdMap();
        if (!isset($map[$id])) {
            return array();
        }
        return $map[$id];
    }
    
    /**
     * Get all certificates in a bundle.
     *
     * @return Certificate[]
     */
    public function all(): array
    {
        return $this->_certs;
    }
    
    /**
     * Get certificate mapping by public key id.
     *
     * @return (Certificate[])[]
     */
    private function _getKeyIdMap(): array
    {
        // lazily build mapping
        if (!isset($this->_keyIdMap)) {
            $this->_keyIdMap = array();
            foreach ($this->_certs as $cert) {
                $id = self::_getCertKeyId($cert);
                if (!isset($this->_keyIdMap[$id])) {
                    $this->_keyIdMap[$id] = array();
                }
                array_push($this->_keyIdMap[$id], $cert);
            }
        }
        return $this->_keyIdMap;
    }
    
    /**
     * Get public key id for the certificate.
     *
     * @param Certificate $cert
     * @return string
     */
    private static function _getCertKeyId(Certificate $cert): string
    {
        $exts = $cert->tbsCertificate()->extensions();
        if ($exts->hasSubjectKeyIdentifier()) {
            return $exts->subjectKeyIdentifier()->keyIdentifier();
        }
        return $cert->tbsCertificate()
            ->subjectPublicKeyInfo()
            ->keyIdentifier();
    }
    
    /**
     *
     * @see \Countable::count()
     * @return int
     */
    public function count(): int
    {
        return count($this->_certs);
    }
    
    /**
     * Get iterator for certificates.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_certs);
    }
}
