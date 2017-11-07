<?php

declare(strict_types = 1);

namespace X509\CertificationRequest;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use X501\ASN1\Attribute;
use X501\ASN1\Name;
use X509\Certificate\Extensions;
use X509\CertificationRequest\Attribute\ExtensionRequestValue;

/**
 * Implements <i>CertificationRequestInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2986#section-4
 */
class CertificationRequestInfo
{
    const VERSION_1 = 0;
    
    /**
     * Version.
     *
     * @var int
     */
    protected $_version;
    
    /**
     * Subject.
     *
     * @var Name $_subject
     */
    protected $_subject;
    
    /**
     * Public key info.
     *
     * @var PublicKeyInfo $_subjectPKInfo
     */
    protected $_subjectPKInfo;
    
    /**
     * Attributes.
     *
     * @var Attributes|null $_attributes
     */
    protected $_attributes;
    
    /**
     * Constructor.
     *
     * @param Name $subject Subject
     * @param PublicKeyInfo $pkinfo Public key info
     */
    public function __construct(Name $subject, PublicKeyInfo $pkinfo)
    {
        $this->_version = self::VERSION_1;
        $this->_subject = $subject;
        $this->_subjectPKInfo = $pkinfo;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $version = $seq->at(0)
            ->asInteger()
            ->intNumber();
        if ($version != self::VERSION_1) {
            throw new \UnexpectedValueException(
                "Version $version not supported.");
        }
        $subject = Name::fromASN1($seq->at(1)->asSequence());
        $pkinfo = PublicKeyInfo::fromASN1($seq->at(2)->asSequence());
        $obj = new self($subject, $pkinfo);
        if ($seq->hasTagged(0)) {
            $obj->_attributes = Attributes::fromASN1(
                $seq->getTagged(0)
                    ->asImplicit(Element::TYPE_SET)
                    ->asSet());
        }
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
     * Get self with subject.
     *
     * @param Name $subject
     * @return self
     */
    public function withSubject(Name $subject): self
    {
        $obj = clone $this;
        $obj->_subject = $subject;
        return $obj;
    }
    
    /**
     * Get subject.
     *
     * @return Name
     */
    public function subject(): Name
    {
        return $this->_subject;
    }
    
    /**
     * Get subject public key info.
     *
     * @return PublicKeyInfo
     */
    public function subjectPKInfo(): PublicKeyInfo
    {
        return $this->_subjectPKInfo;
    }
    
    /**
     * Whether certification request info has attributes.
     *
     * @return bool
     */
    public function hasAttributes(): bool
    {
        return isset($this->_attributes);
    }
    
    /**
     * Get attributes.
     *
     * @throws \LogicException
     * @return Attributes
     */
    public function attributes(): Attributes
    {
        if (!$this->hasAttributes()) {
            throw new \LogicException("No attributes.");
        }
        return $this->_attributes;
    }
    
    /**
     * Get instance of self with attributes.
     *
     * @param Attributes $attribs
     */
    public function withAttributes(Attributes $attribs): self
    {
        $obj = clone $this;
        $obj->_attributes = $attribs;
        return $obj;
    }
    
    /**
     * Get self with extension request attribute.
     *
     * @param Extensions $extensions Extensions to request
     * @return self
     */
    public function withExtensionRequest(Extensions $extensions): self
    {
        $obj = clone $this;
        if (!isset($obj->_attributes)) {
            $obj->_attributes = new Attributes();
        }
        $obj->_attributes = $obj->_attributes->withUnique(
            Attribute::fromAttributeValues(
                new ExtensionRequestValue($extensions)));
        return $obj;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array(new Integer($this->_version),
            $this->_subject->toASN1(), $this->_subjectPKInfo->toASN1());
        if (isset($this->_attributes)) {
            $elements[] = new ImplicitlyTaggedType(0,
                $this->_attributes->toASN1());
        }
        return new Sequence(...$elements);
    }
    
    /**
     * Create signed CertificationRequest.
     *
     * @param SignatureAlgorithmIdentifier $algo Algorithm used for signing
     * @param PrivateKeyInfo $privkey_info Private key used for signing
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return CertificationRequest
     */
    public function sign(SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info, Crypto $crypto = null): CertificationRequest
    {
        $crypto = $crypto ?: Crypto::getDefault();
        $data = $this->toASN1()->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new CertificationRequest($this, $algo, $signature);
    }
}
