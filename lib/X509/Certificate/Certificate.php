<?php

namespace X509\Certificate;

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Implements <i>Certificate</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1
 */
class Certificate
{
    /**
     * "To be signed" certificate information.
     *
     * @var TBSCertificate $_tbsCertificate
     */
    protected $_tbsCertificate;
    
    /**
     * Signature algorithm.
     *
     * @var SignatureAlgorithmIdentifier $_signatureAlgorithm
     */
    protected $_signatureAlgorithm;
    
    /**
     * Signature value.
     *
     * @var Signature $_signatureValue
     */
    protected $_signatureValue;
    
    /**
     * Constructor.
     *
     * @param TBSCertificate $tbsCert
     * @param SignatureAlgorithmIdentifier $algo
     * @param Signature $signature
     */
    public function __construct(TBSCertificate $tbsCert,
        SignatureAlgorithmIdentifier $algo, Signature $signature)
    {
        $this->_tbsCertificate = $tbsCert;
        $this->_signatureAlgorithm = $algo;
        $this->_signatureValue = $signature;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $tbsCert = TBSCertificate::fromASN1($seq->at(0)->asSequence());
        $algo = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                "Unsupported signature algorithm " . $algo->oid() . ".");
        }
        $signature = Signature::fromSignatureData(
            $seq->at(2)
                ->asBitString()
                ->string(), $algo);
        return new self($tbsCert, $algo, $signature);
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
        if ($pem->type() != PEM::TYPE_CERTIFICATE) {
            throw new \UnexpectedValueException("Invalid PEM type.");
        }
        return self::fromDER($pem->data());
    }
    
    /**
     * Get certificate information.
     *
     * @return TBSCertificate
     */
    public function tbsCertificate()
    {
        return $this->_tbsCertificate;
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
     * Get signature value.
     *
     * @return Signature
     */
    public function signatureValue()
    {
        return $this->_signatureValue;
    }
    
    /**
     * Check whether certificate is self-issued.
     *
     * @return bool
     */
    public function isSelfIssued()
    {
        return $this->_tbsCertificate->subject()->equals(
            $this->_tbsCertificate->issuer());
    }
    
    /**
     * Check whether certificate is semantically equal to another.
     *
     * @param Certificate $cert Certificate to compare to
     * @return bool
     */
    public function equals(Certificate $cert)
    {
        return $this->_hasEqualSerialNumber($cert) &&
             $this->_hasEqualPublicKey($cert) && $this->_hasEqualSubject($cert);
    }
    
    /**
     * Check whether certificate has serial number equal to another.
     *
     * @param Certificate $cert
     * @return bool
     */
    private function _hasEqualSerialNumber(Certificate $cert)
    {
        $sn1 = $this->_tbsCertificate->serialNumber();
        $sn2 = $cert->_tbsCertificate->serialNumber();
        return $sn1 == $sn2;
    }
    
    /**
     * Check whether certificate has public key equal to another.
     *
     * @param Certificate $cert
     * @return bool
     */
    private function _hasEqualPublicKey(Certificate $cert)
    {
        $kid1 = $this->_tbsCertificate->subjectPublicKeyInfo()->keyIdentifier();
        $kid2 = $cert->_tbsCertificate->subjectPublicKeyInfo()->keyIdentifier();
        return $kid1 == $kid2;
    }
    
    /**
     * Check whether certificate has subject equal to another.
     *
     * @param Certificate $cert
     * @return bool
     */
    private function _hasEqualSubject(Certificate $cert)
    {
        $dn1 = $this->_tbsCertificate->subject();
        $dn2 = $cert->_tbsCertificate->subject();
        return $dn1->equals($dn2);
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        return new Sequence($this->_tbsCertificate->toASN1(),
            $this->_signatureAlgorithm->toASN1(),
            $this->_signatureValue->bitString());
    }
    
    /**
     * Get certificate as a DER.
     *
     * @return string
     */
    public function toDER()
    {
        return $this->toASN1()->toDER();
    }
    
    /**
     * Get certificate as a PEM.
     *
     * @return PEM
     */
    public function toPEM()
    {
        return new PEM(PEM::TYPE_CERTIFICATE, $this->toDER());
    }
    
    /**
     * Verify certificate signature.
     *
     * @param Crypto $crypto
     * @param PublicKeyInfo $pubkey_info Issuer's public key
     * @return bool True if certificate signature is valid
     */
    public function verify(Crypto $crypto, PublicKeyInfo $pubkey_info)
    {
        $data = $this->_tbsCertificate->toASN1()->toDER();
        return $crypto->verify($data, $this->_signatureValue, $pubkey_info,
            $this->_signatureAlgorithm);
    }
    
    /**
     * Get certificate as a PEM formatted string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toPEM()->string();
    }
}
