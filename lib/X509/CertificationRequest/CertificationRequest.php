<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationRequest;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Implements *CertificationRequest* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc2986#section-4
 */
class CertificationRequest
{
    /**
     * Certification request info.
     *
     * @var CertificationRequestInfo
     */
    protected $_certificationRequestInfo;

    /**
     * Signature algorithm.
     *
     * @var SignatureAlgorithmIdentifier
     */
    protected $_signatureAlgorithm;

    /**
     * Signature.
     *
     * @var Signature
     */
    protected $_signature;

    /**
     * Constructor.
     */
    public function __construct(CertificationRequestInfo $info,
        SignatureAlgorithmIdentifier $algo, Signature $signature)
    {
        $this->_certificationRequestInfo = $info;
        $this->_signatureAlgorithm = $algo;
        $this->_signature = $signature;
    }

    /**
     * Get certification request as a PEM formatted string.
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
        $info = CertificationRequestInfo::fromASN1($seq->at(0)->asSequence());
        $algo = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                'Unsupported signature algorithm ' . $algo->oid() . '.');
        }
        $signature = Signature::fromSignatureData(
            $seq->at(2)->asBitString()->string(), $algo);
        return new self($info, $algo, $signature);
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
        if (PEM::TYPE_CERTIFICATE_REQUEST !== $pem->type()) {
            throw new \UnexpectedValueException('Invalid PEM type.');
        }
        return self::fromDER($pem->data());
    }

    /**
     * Get certification request info.
     */
    public function certificationRequestInfo(): CertificationRequestInfo
    {
        return $this->_certificationRequestInfo;
    }

    /**
     * Get signature algorithm.
     */
    public function signatureAlgorithm(): SignatureAlgorithmIdentifier
    {
        return $this->_signatureAlgorithm;
    }

    /**
     * Get signature.
     */
    public function signature(): Signature
    {
        return $this->_signature;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_certificationRequestInfo->toASN1(),
            $this->_signatureAlgorithm->toASN1(), $this->_signature->bitString());
    }

    /**
     * Get certification request as a DER.
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * Get certification request as a PEM.
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_CERTIFICATE_REQUEST, $this->toDER());
    }

    /**
     * Verify certification request signature.
     *
     * @param null|Crypto $crypto Crypto engine, use default if not set
     *
     * @return bool True if signature matches
     */
    public function verify(?Crypto $crypto = null): bool
    {
        $crypto = $crypto ?? Crypto::getDefault();
        $data = $this->_certificationRequestInfo->toASN1()->toDER();
        $pk_info = $this->_certificationRequestInfo->subjectPKInfo();
        return $crypto->verify($data, $this->_signature, $pk_info,
            $this->_signatureAlgorithm);
    }
}
