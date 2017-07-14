<?php

namespace X509\CertificationRequest;

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Implements <i>CertificationRequest</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2986#section-4
 */
class CertificationRequest
{
    /**
     * Certification request info.
     *
     * @var CertificationRequestInfo $_certificationRequestInfo
     */
    protected $_certificationRequestInfo;
    
    /**
     * Signature algorithm.
     *
     * @var SignatureAlgorithmIdentifier $_signatureAlgorithm
     */
    protected $_signatureAlgorithm;
    
    /**
     * Signature.
     *
     * @var Signature $_signature
     */
    protected $_signature;
    
    /**
     * Constructor.
     *
     * @param CertificationRequestInfo $info
     * @param SignatureAlgorithmIdentifier $algo
     * @param Signature $signature
     */
    public function __construct(CertificationRequestInfo $info,
        SignatureAlgorithmIdentifier $algo, Signature $signature)
    {
        $this->_certificationRequestInfo = $info;
        $this->_signatureAlgorithm = $algo;
        $this->_signature = $signature;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $info = CertificationRequestInfo::fromASN1($seq->at(0)->asSequence());
        $algo = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                "Unsupported signature algorithm " . $algo->oid() . ".");
        }
        $signature = Signature::fromSignatureData(
            $seq->at(2)
                ->asBitString()
                ->string(), $algo);
        return new self($info, $algo, $signature);
    }
    
    /**
     * Initialize from DER.
     *
     * @param string $data
     * @return self
     */
    public static function fromDER($data)
    {
        return self::fromASN1(Sequence::fromDER($data));
    }
    
    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromPEM(PEM $pem)
    {
        if ($pem->type() !== PEM::TYPE_CERTIFICATE_REQUEST) {
            throw new \UnexpectedValueException("Invalid PEM type.");
        }
        return self::fromDER($pem->data());
    }
    
    /**
     * Get certification request info.
     *
     * @return CertificationRequestInfo
     */
    public function certificationRequestInfo()
    {
        return $this->_certificationRequestInfo;
    }
    
    /**
     * Get signature algorithm.
     *
     * @return SignatureAlgorithmIdentifier
     */
    public function signatureAlgorithm()
    {
        return $this->_signatureAlgorithm;
    }
    
    /**
     * Get signature.
     *
     * @return Signature
     */
    public function signature()
    {
        return $this->_signature;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        return new Sequence($this->_certificationRequestInfo->toASN1(),
            $this->_signatureAlgorithm->toASN1(), $this->_signature->bitString());
    }
    
    /**
     * Get certification request as a DER.
     *
     * @return string
     */
    public function toDER()
    {
        return $this->toASN1()->toDER();
    }
    
    /**
     * Get certification request as a PEM.
     *
     * @return PEM
     */
    public function toPEM()
    {
        return new PEM(PEM::TYPE_CERTIFICATE_REQUEST, $this->toDER());
    }
    
    /**
     * Verify certification request signature.
     *
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return bool True if signature matches
     */
    public function verify(Crypto $crypto = null)
    {
        $crypto = $crypto ?: Crypto::getDefault();
        $data = $this->_certificationRequestInfo->toASN1()->toDER();
        $pk_info = $this->_certificationRequestInfo->subjectPKInfo();
        return $crypto->verify($data, $this->_signature, $pk_info,
            $this->_signatureAlgorithm);
    }
    
    /**
     * Get certification request as a PEM formatted string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toPEM()->string();
    }
}
