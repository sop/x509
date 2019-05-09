<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X509\Certificate\Certificate;

/**
 * Implements <i>AttributeCertificate</i> ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
class AttributeCertificate
{
    /**
     * Attribute certificate info.
     *
     * @var AttributeCertificateInfo
     */
    protected $_acinfo;

    /**
     * Signature algorithm identifier.
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
     *
     * @param AttributeCertificateInfo     $acinfo
     * @param SignatureAlgorithmIdentifier $algo
     * @param Signature                    $signature
     */
    public function __construct(AttributeCertificateInfo $acinfo,
        SignatureAlgorithmIdentifier $algo, Signature $signature)
    {
        $this->_acinfo = $acinfo;
        $this->_signatureAlgorithm = $algo;
        $this->_signatureValue = $signature;
    }

    /**
     * Get attribute certificate as a PEM formatted string.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toPEM()->string();
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $acinfo = AttributeCertificateInfo::fromASN1($seq->at(0)->asSequence());
        $algo = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                'Unsupported signature algorithm ' . $algo->oid() . '.');
        }
        $signature = Signature::fromSignatureData(
            $seq->at(2)->asBitString()->string(), $algo);
        return new self($acinfo, $algo, $signature);
    }

    /**
     * Initialize from DER data.
     *
     * @param string $data
     *
     * @return self
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        if (PEM::TYPE_ATTRIBUTE_CERTIFICATE !== $pem->type()) {
            throw new \UnexpectedValueException('Invalid PEM type.');
        }
        return self::fromDER($pem->data());
    }

    /**
     * Get attribute certificate info.
     *
     * @return AttributeCertificateInfo
     */
    public function acinfo(): AttributeCertificateInfo
    {
        return $this->_acinfo;
    }

    /**
     * Get signature algorithm identifier.
     *
     * @return SignatureAlgorithmIdentifier
     */
    public function signatureAlgorithm(): SignatureAlgorithmIdentifier
    {
        return $this->_signatureAlgorithm;
    }

    /**
     * Get signature value.
     *
     * @return Signature
     */
    public function signatureValue(): Signature
    {
        return $this->_signatureValue;
    }

    /**
     * Get ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_acinfo->toASN1(),
            $this->_signatureAlgorithm->toASN1(),
            $this->_signatureValue->bitString());
    }

    /**
     * Get attribute certificate as a DER.
     *
     * @return string
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * Get attribute certificate as a PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $this->toDER());
    }

    /**
     * Check whether attribute certificate is issued to the subject identified
     * by given public key certificate.
     *
     * @param Certificate $cert Certificate
     *
     * @return bool
     */
    public function isHeldBy(Certificate $cert): bool
    {
        if (!$this->_acinfo->holder()->identifiesPKC($cert)) {
            return false;
        }
        return true;
    }

    /**
     * Check whether attribute certificate is issued by given public key
     * certificate.
     *
     * @param Certificate $cert Certificate
     *
     * @return bool
     */
    public function isIssuedBy(Certificate $cert): bool
    {
        if (!$this->_acinfo->issuer()->identifiesPKC($cert)) {
            return false;
        }
        return true;
    }

    /**
     * Verify signature.
     *
     * @param PublicKeyInfo $pubkey_info Signer's public key
     * @param null|Crypto   $crypto      Crypto engine, use default if not set
     *
     * @return bool
     */
    public function verify(PublicKeyInfo $pubkey_info, ?Crypto $crypto = null): bool
    {
        $crypto = $crypto ?? Crypto::getDefault();
        $data = $this->_acinfo->toASN1()->toDER();
        return $crypto->verify($data, $this->_signatureValue, $pubkey_info,
            $this->_signatureAlgorithm);
    }
}
