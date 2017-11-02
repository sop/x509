<?php

declare(strict_types=1);

namespace X509\AttributeCertificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use X509\Certificate\Extensions;
use X509\Certificate\UniqueIdentifier;
use X509\Certificate\Extension\Extension;

/**
 * Implements <i>AttributeCertificateInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 */
class AttributeCertificateInfo
{
    const VERSION_2 = 1;
    
    /**
     * AC version.
     *
     * @var int $_version
     */
    protected $_version;
    
    /**
     * AC holder.
     *
     * @var Holder $_holder
     */
    protected $_holder;
    
    /**
     * AC issuer.
     *
     * @var AttCertIssuer $_issuer
     */
    protected $_issuer;
    
    /**
     * Signature algorithm identifier.
     *
     * @var SignatureAlgorithmIdentifier $_signature
     */
    protected $_signature;
    
    /**
     * AC serial number.
     *
     * @var int|string $_serialNumber
     */
    protected $_serialNumber;
    
    /**
     * Validity period.
     *
     * @var AttCertValidityPeriod $_attrCertValidityPeriod
     */
    protected $_attrCertValidityPeriod;
    
    /**
     * Attributes.
     *
     * @var Attributes $_attributes
     */
    protected $_attributes;
    
    /**
     * Issuer unique identifier.
     *
     * @var UniqueIdentifier|null $_issuerUniqueID
     */
    protected $_issuerUniqueID;
    
    /**
     * Extensions.
     *
     * @var Extensions $_extensions
     */
    protected $_extensions;
    
    /**
     * Constructor.
     *
     * @param Holder $holder AC holder
     * @param AttCertIssuer $issuer AC issuer
     * @param AttCertValidityPeriod $validity Validity
     * @param Attributes $attribs Attributes
     */
    public function __construct(Holder $holder, AttCertIssuer $issuer,
        AttCertValidityPeriod $validity, Attributes $attribs)
    {
        $this->_version = self::VERSION_2;
        $this->_holder = $holder;
        $this->_issuer = $issuer;
        $this->_attrCertValidityPeriod = $validity;
        $this->_attributes = $attribs;
        $this->_extensions = new Extensions();
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $version = $seq->at(0)
            ->asInteger()
            ->number();
        if ($version != self::VERSION_2) {
            throw new \UnexpectedValueException("Version must be 2.");
        }
        $holder = Holder::fromASN1($seq->at(1)->asSequence());
        $issuer = AttCertIssuer::fromASN1($seq->at(2));
        $signature = AlgorithmIdentifier::fromASN1($seq->at(3)->asSequence());
        if (!$signature instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                "Unsupported signature algorithm " . $signature->oid() . ".");
        }
        $serial = $seq->at(4)
            ->asInteger()
            ->number();
        $validity = AttCertValidityPeriod::fromASN1($seq->at(5)->asSequence());
        $attribs = Attributes::fromASN1($seq->at(6)->asSequence());
        $obj = new self($holder, $issuer, $validity, $attribs);
        $obj->_signature = $signature;
        $obj->_serialNumber = $serial;
        $idx = 7;
        if ($seq->has($idx, Element::TYPE_BIT_STRING)) {
            $obj->_issuerUniqueID = UniqueIdentifier::fromASN1(
                $seq->at($idx++)->asBitString());
        }
        if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
            $obj->_extensions = Extensions::fromASN1(
                $seq->at($idx++)->asSequence());
        }
        return $obj;
    }
    
    /**
     * Get self with holder.
     *
     * @param Holder $holder
     * @return self
     */
    public function withHolder(Holder $holder)
    {
        $obj = clone $this;
        $obj->_holder = $holder;
        return $obj;
    }
    
    /**
     * Get self with issuer.
     *
     * @param AttCertIssuer $issuer
     * @return self
     */
    public function withIssuer(AttCertIssuer $issuer)
    {
        $obj = clone $this;
        $obj->_issuer = $issuer;
        return $obj;
    }
    
    /**
     * Get self with signature algorithm identifier.
     *
     * @param SignatureAlgorithmIdentifier $algo
     * @return self
     */
    public function withSignature(SignatureAlgorithmIdentifier $algo)
    {
        $obj = clone $this;
        $obj->_signature = $algo;
        return $obj;
    }
    
    /**
     * Get self with serial number.
     *
     * @param int|string $serial
     * @return self
     */
    public function withSerialNumber($serial)
    {
        $obj = clone $this;
        $obj->_serialNumber = $serial;
        return $obj;
    }
    
    /**
     * Get self with random positive serial number.
     *
     * @param int $size Number of random bytes
     * @return self
     */
    public function withRandomSerialNumber(int $size = 16)
    {
        // ensure that first byte is always non-zero and having first bit unset
        $num = gmp_init(mt_rand(1, 0x7f), 10);
        for ($i = 1; $i < $size; ++$i) {
            $num <<= 8;
            $num += mt_rand(0, 0xff);
        }
        return $this->withSerialNumber(gmp_strval($num, 10));
    }
    
    /**
     * Get self with validity period.
     *
     * @param AttCertValidityPeriod $validity
     * @return self
     */
    public function withValidity(AttCertValidityPeriod $validity)
    {
        $obj = clone $this;
        $obj->_attrCertValidityPeriod = $validity;
        return $obj;
    }
    
    /**
     * Get self with attributes.
     *
     * @param Attributes $attribs
     * @return self
     */
    public function withAttributes(Attributes $attribs)
    {
        $obj = clone $this;
        $obj->_attributes = $attribs;
        return $obj;
    }
    
    /**
     * Get self with issuer unique identifier.
     *
     * @param UniqueIdentifier $uid
     * @return self
     */
    public function withIssuerUniqueID(UniqueIdentifier $uid)
    {
        $obj = clone $this;
        $obj->_issuerUniqueID = $uid;
        return $obj;
    }
    
    /**
     * Get self with extensions.
     *
     * @param Extensions $extensions
     * @return self
     */
    public function withExtensions(Extensions $extensions)
    {
        $obj = clone $this;
        $obj->_extensions = $extensions;
        return $obj;
    }
    
    /**
     * Get self with extensions added.
     *
     * @param Extension ...$exts One or more Extension objects
     * @return self
     */
    public function withAdditionalExtensions(Extension ...$exts)
    {
        $obj = clone $this;
        $obj->_extensions = $obj->_extensions->withExtensions(...$exts);
        return $obj;
    }
    
    /**
     * Get version.
     *
     * @return int
     */
    public function version(): int
    {
        return $this->_version;
    }
    
    /**
     * Get AC holder.
     *
     * @return Holder
     */
    public function holder(): Holder
    {
        return $this->_holder;
    }
    
    /**
     * Get AC issuer.
     *
     * @return AttCertIssuer
     */
    public function issuer(): AttCertIssuer
    {
        return $this->_issuer;
    }
    
    /**
     * Check whether signature is set.
     *
     * @return bool
     */
    public function hasSignature(): bool
    {
        return isset($this->_signature);
    }
    
    /**
     * Get signature algorithm identifier.
     *
     * @return SignatureAlgorithmIdentifier
     */
    public function signature(): SignatureAlgorithmIdentifier
    {
        if (!$this->hasSignature()) {
            throw new \LogicException("signature not set.");
        }
        return $this->_signature;
    }
    
    /**
     * Check whether serial number is present.
     *
     * @return bool
     */
    public function hasSerialNumber(): bool
    {
        return isset($this->_serialNumber);
    }
    
    /**
     * Get AC serial number.
     *
     * @return int|string
     */
    public function serialNumber()
    {
        if (!$this->hasSerialNumber()) {
            throw new \LogicException("serialNumber not set.");
        }
        return $this->_serialNumber;
    }
    
    /**
     * Get validity period.
     *
     * @return AttCertValidityPeriod
     */
    public function validityPeriod(): AttCertValidityPeriod
    {
        return $this->_attrCertValidityPeriod;
    }
    
    /**
     * Get attributes.
     *
     * @return Attributes
     */
    public function attributes(): Attributes
    {
        return $this->_attributes;
    }
    
    /**
     * Check whether issuer unique identifier is present.
     *
     * @return bool
     */
    public function hasIssuerUniqueID(): bool
    {
        return isset($this->_issuerUniqueID);
    }
    
    /**
     * Get issuer unique identifier.
     *
     * @return UniqueIdentifier
     */
    public function issuerUniqueID(): UniqueIdentifier
    {
        if (!$this->hasIssuerUniqueID()) {
            throw new \LogicException("issuerUniqueID not set.");
        }
        return $this->_issuerUniqueID;
    }
    
    /**
     * Get extensions.
     *
     * @return Extensions
     */
    public function extensions(): Extensions
    {
        return $this->_extensions;
    }
    
    /**
     * Get ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array(new Integer($this->_version), $this->_holder->toASN1(),
            $this->_issuer->toASN1(), $this->signature()->toASN1(),
            new Integer($this->serialNumber()),
            $this->_attrCertValidityPeriod->toASN1(),
            $this->_attributes->toASN1());
        if (isset($this->_issuerUniqueID)) {
            $elements[] = $this->_issuerUniqueID->toASN1();
        }
        if (count($this->_extensions)) {
            $elements[] = $this->_extensions->toASN1();
        }
        return new Sequence(...$elements);
    }
    
    /**
     * Create signed attribute certificate.
     *
     * @param SignatureAlgorithmIdentifier $algo Signature algorithm
     * @param PrivateKeyInfo $privkey_info Private key
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return AttributeCertificate
     */
    public function sign(SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info, Crypto $crypto = null): AttributeCertificate
    {
        $crypto = $crypto ?: Crypto::getDefault();
        $aci = clone $this;
        if (!isset($aci->_serialNumber)) {
            $aci->_serialNumber = 0;
        }
        $aci->_signature = $algo;
        $data = $aci->toASN1()->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new AttributeCertificate($aci, $algo, $signature);
    }
}
