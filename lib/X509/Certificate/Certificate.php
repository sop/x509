<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Implements *Certificate* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1
 */
class Certificate
{
    /**
     * "To be signed" certificate information.
     *
     * @var TBSCertificate
     */
    protected $_tbsCertificate;

    /**
     * Signature algorithm.
     *
     * @var SignatureAlgorithmIdentifier
     */
    protected $_signatureAlgorithm;

    /**
     * Signature value.
     *
     * @var Signature
     */
    protected $_signatureValue;

    /**
     * Constructor.
     */
    public function __construct(TBSCertificate $tbsCert,
        SignatureAlgorithmIdentifier $algo, Signature $signature)
    {
        $this->_tbsCertificate = $tbsCert;
        $this->_signatureAlgorithm = $algo;
        $this->_signatureValue = $signature;
    }

    /**
     * Get certificate as a PEM formatted string.
     */
    public function __toString(): string
    {
        return $this->toPEM()->string();
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $tbsCert = TBSCertificate::fromASN1($seq->at(0)->asSequence());
        $algo = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                'Unsupported signature algorithm ' . $algo->oid() . '.');
        }
        $signature = Signature::fromSignatureData(
            $seq->at(2)->asBitString()->string(), $algo);
        return new self($tbsCert, $algo, $signature);
    }

    /**
     * Initialize from DER.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Initialize from PEM.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromPEM(PEM $pem): self
    {
        if (PEM::TYPE_CERTIFICATE !== $pem->type()) {
            throw new \UnexpectedValueException('Invalid PEM type.');
        }
        return self::fromDER($pem->data());
    }

    /**
     * Get certificate information.
     */
    public function tbsCertificate(): TBSCertificate
    {
        return $this->_tbsCertificate;
    }

    /**
     * Get signature algorithm.
     */
    public function signatureAlgorithm(): SignatureAlgorithmIdentifier
    {
        return $this->_signatureAlgorithm;
    }

    /**
     * Get signature value.
     */
    public function signatureValue(): Signature
    {
        return $this->_signatureValue;
    }

    /**
     * Check whether certificate is self-issued.
     */
    public function isSelfIssued(): bool
    {
        return $this->_tbsCertificate->subject()->equals(
            $this->_tbsCertificate->issuer());
    }

    /**
     * Check whether certificate is semantically equal to another.
     *
     * @param Certificate $cert Certificate to compare to
     */
    public function equals(Certificate $cert): bool
    {
        return $this->_hasEqualSerialNumber($cert)
             && $this->_hasEqualPublicKey($cert) && $this->_hasEqualSubject($cert);
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_tbsCertificate->toASN1(),
            $this->_signatureAlgorithm->toASN1(),
            $this->_signatureValue->bitString());
    }

    /**
     * Get certificate as a DER.
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * Get certificate as a PEM.
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_CERTIFICATE, $this->toDER());
    }

    /**
     * Verify certificate signature.
     *
     * @param PublicKeyInfo $pubkey_info Issuer's public key
     * @param null|Crypto   $crypto      Crypto engine, use default if not set
     *
     * @return bool True if certificate signature is valid
     */
    public function verify(PublicKeyInfo $pubkey_info, ?Crypto $crypto = null): bool
    {
        $crypto = $crypto ?? Crypto::getDefault();
        $data = $this->_tbsCertificate->toASN1()->toDER();
        return $crypto->verify($data, $this->_signatureValue, $pubkey_info,
            $this->_signatureAlgorithm);
    }

    /**
     * Check whether certificate has serial number equal to another.
     */
    private function _hasEqualSerialNumber(Certificate $cert): bool
    {
        $sn1 = $this->_tbsCertificate->serialNumber();
        $sn2 = $cert->_tbsCertificate->serialNumber();
        return $sn1 === $sn2;
    }

    /**
     * Check whether certificate has public key equal to another.
     */
    private function _hasEqualPublicKey(Certificate $cert): bool
    {
        $kid1 = $this->_tbsCertificate->subjectPublicKeyInfo()->keyIdentifier();
        $kid2 = $cert->_tbsCertificate->subjectPublicKeyInfo()->keyIdentifier();
        return $kid1 === $kid2;
    }

    /**
     * Check whether certificate has subject equal to another.
     */
    private function _hasEqualSubject(Certificate $cert): bool
    {
        $dn1 = $this->_tbsCertificate->subject();
        $dn2 = $cert->_tbsCertificate->subject();
        return $dn1->equals($dn2);
    }
}
