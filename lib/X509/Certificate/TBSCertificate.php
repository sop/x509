<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use Sop\X509\CertificationRequest\CertificationRequest;

/**
 * Implements <i>TBSCertificate</i> ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2
 */
class TBSCertificate
{
    // Certificate version enumerations
    const VERSION_1 = 0;
    const VERSION_2 = 1;
    const VERSION_3 = 2;

    /**
     * Certificate version.
     *
     * @var null|int
     */
    protected $_version;

    /**
     * Serial number.
     *
     * @var null|string
     */
    protected $_serialNumber;

    /**
     * Signature algorithm.
     *
     * @var null|SignatureAlgorithmIdentifier
     */
    protected $_signature;

    /**
     * Certificate issuer.
     *
     * @var Name
     */
    protected $_issuer;

    /**
     * Certificate validity period.
     *
     * @var Validity
     */
    protected $_validity;

    /**
     * Certificate subject.
     *
     * @var Name
     */
    protected $_subject;

    /**
     * Subject public key.
     *
     * @var PublicKeyInfo
     */
    protected $_subjectPublicKeyInfo;

    /**
     * Issuer unique identifier.
     *
     * @var null|UniqueIdentifier
     */
    protected $_issuerUniqueID;

    /**
     * Subject unique identifier.
     *
     * @var null|UniqueIdentifier
     */
    protected $_subjectUniqueID;

    /**
     * Extensions.
     *
     * @var Extensions
     */
    protected $_extensions;

    /**
     * Constructor.
     *
     * @param Name          $subject  Certificate subject
     * @param PublicKeyInfo $pki      Subject public key
     * @param Name          $issuer   Certificate issuer
     * @param Validity      $validity Validity period
     */
    public function __construct(Name $subject, PublicKeyInfo $pki, Name $issuer,
        Validity $validity)
    {
        $this->_subject = $subject;
        $this->_subjectPublicKeyInfo = $pki;
        $this->_issuer = $issuer;
        $this->_validity = $validity;
        $this->_extensions = new Extensions();
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
        $idx = 0;
        if ($seq->hasTagged(0)) {
            ++$idx;
            $version = $seq->getTagged(0)->asExplicit()->asInteger()->intNumber();
        } else {
            $version = self::VERSION_1;
        }
        $serial = $seq->at($idx++)->asInteger()->number();
        $algo = AlgorithmIdentifier::fromASN1($seq->at($idx++)->asSequence());
        if (!$algo instanceof SignatureAlgorithmIdentifier) {
            throw new \UnexpectedValueException(
                'Unsupported signature algorithm ' . $algo->name() . '.');
        }
        $issuer = Name::fromASN1($seq->at($idx++)->asSequence());
        $validity = Validity::fromASN1($seq->at($idx++)->asSequence());
        $subject = Name::fromASN1($seq->at($idx++)->asSequence());
        $pki = PublicKeyInfo::fromASN1($seq->at($idx++)->asSequence());
        $tbs_cert = new self($subject, $pki, $issuer, $validity);
        $tbs_cert->_version = $version;
        $tbs_cert->_serialNumber = $serial;
        $tbs_cert->_signature = $algo;
        if ($seq->hasTagged(1)) {
            $tbs_cert->_issuerUniqueID = UniqueIdentifier::fromASN1(
                $seq->getTagged(1)->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString());
        }
        if ($seq->hasTagged(2)) {
            $tbs_cert->_subjectUniqueID = UniqueIdentifier::fromASN1(
                $seq->getTagged(2)->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString());
        }
        if ($seq->hasTagged(3)) {
            $tbs_cert->_extensions = Extensions::fromASN1(
                $seq->getTagged(3)->asExplicit()->asSequence());
        }
        return $tbs_cert;
    }

    /**
     * Initialize from certification request.
     *
     * Note that signature is not verified and must be done by the caller.
     *
     * @param CertificationRequest $cr
     *
     * @return self
     */
    public static function fromCSR(CertificationRequest $cr): self
    {
        $cri = $cr->certificationRequestInfo();
        $tbs_cert = new self($cri->subject(), $cri->subjectPKInfo(), new Name(),
            Validity::fromStrings(null, null));
        // if CSR has Extension Request attribute
        if ($cri->hasAttributes()) {
            $attribs = $cri->attributes();
            if ($attribs->hasExtensionRequest()) {
                $tbs_cert = $tbs_cert->withExtensions(
                    $attribs->extensionRequest()->extensions());
            }
        }
        // add Subject Key Identifier extension
        return $tbs_cert->withAdditionalExtensions(
            new SubjectKeyIdentifierExtension(false,
                $cri->subjectPKInfo()->keyIdentifier()));
    }

    /**
     * Get self with fields set from the issuer's certificate.
     *
     * Issuer shall be set to issuing certificate's subject.
     * Authority key identifier extensions shall be added with a key identifier
     * set to issuing certificate's public key identifier.
     *
     * @param Certificate $cert Issuing party's certificate
     *
     * @return self
     */
    public function withIssuerCertificate(Certificate $cert): self
    {
        $obj = clone $this;
        // set issuer DN from cert's subject
        $obj->_issuer = $cert->tbsCertificate()->subject();
        // add authority key identifier extension
        $key_id = $cert->tbsCertificate()->subjectPublicKeyInfo()->keyIdentifier();
        $obj->_extensions = $obj->_extensions->withExtensions(
            new AuthorityKeyIdentifierExtension(false, $key_id));
        return $obj;
    }

    /**
     * Get self with given version.
     *
     * If version is not set, appropriate version is automatically
     * determined during signing.
     *
     * @param int $version
     *
     * @return self
     */
    public function withVersion(int $version): self
    {
        $obj = clone $this;
        $obj->_version = $version;
        return $obj;
    }

    /**
     * Get self with given serial number.
     *
     * @param int|string $serial Base 10 number
     *
     * @return self
     */
    public function withSerialNumber($serial): self
    {
        $obj = clone $this;
        $obj->_serialNumber = strval($serial);
        return $obj;
    }

    /**
     * Get self with random positive serial number.
     *
     * @param int $size Number of random bytes
     *
     * @return self
     */
    public function withRandomSerialNumber(int $size = 16): self
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
     * Get self with given signature algorithm.
     *
     * @param SignatureAlgorithmIdentifier $algo
     *
     * @return self
     */
    public function withSignature(SignatureAlgorithmIdentifier $algo): self
    {
        $obj = clone $this;
        $obj->_signature = $algo;
        return $obj;
    }

    /**
     * Get self with given issuer.
     *
     * @param Name $issuer
     *
     * @return self
     */
    public function withIssuer(Name $issuer): self
    {
        $obj = clone $this;
        $obj->_issuer = $issuer;
        return $obj;
    }

    /**
     * Get self with given validity.
     *
     * @param Validity $validity
     *
     * @return self
     */
    public function withValidity(Validity $validity): self
    {
        $obj = clone $this;
        $obj->_validity = $validity;
        return $obj;
    }

    /**
     * Get self with given subject.
     *
     * @param Name $subject
     *
     * @return self
     */
    public function withSubject(Name $subject): self
    {
        $obj = clone $this;
        $obj->_subject = $subject;
        return $obj;
    }

    /**
     * Get self with given subject public key info.
     *
     * @param PublicKeyInfo $pub_key_info
     *
     * @return self
     */
    public function withSubjectPublicKeyInfo(PublicKeyInfo $pub_key_info): self
    {
        $obj = clone $this;
        $obj->_subjectPublicKeyInfo = $pub_key_info;
        return $obj;
    }

    /**
     * Get self with issuer unique ID.
     *
     * @param UniqueIdentifier $id
     *
     * @return self
     */
    public function withIssuerUniqueID(UniqueIdentifier $id): self
    {
        $obj = clone $this;
        $obj->_issuerUniqueID = $id;
        return $obj;
    }

    /**
     * Get self with subject unique ID.
     *
     * @param UniqueIdentifier $id
     *
     * @return self
     */
    public function withSubjectUniqueID(UniqueIdentifier $id): self
    {
        $obj = clone $this;
        $obj->_subjectUniqueID = $id;
        return $obj;
    }

    /**
     * Get self with given extensions.
     *
     * @param Extensions $extensions
     *
     * @return self
     */
    public function withExtensions(Extensions $extensions): self
    {
        $obj = clone $this;
        $obj->_extensions = $extensions;
        return $obj;
    }

    /**
     * Get self with extensions added.
     *
     * @param Extension ...$exts One or more Extension objects
     *
     * @return self
     */
    public function withAdditionalExtensions(Extension ...$exts): self
    {
        $obj = clone $this;
        $obj->_extensions = $obj->_extensions->withExtensions(...$exts);
        return $obj;
    }

    /**
     * Check whether version is set.
     *
     * @return bool
     */
    public function hasVersion(): bool
    {
        return isset($this->_version);
    }

    /**
     * Get certificate version.
     *
     * @throws \LogicException If not set
     *
     * @return int
     */
    public function version(): int
    {
        if (!$this->hasVersion()) {
            throw new \LogicException('version not set.');
        }
        return $this->_version;
    }

    /**
     * Check whether serial number is set.
     *
     * @return bool
     */
    public function hasSerialNumber(): bool
    {
        return isset($this->_serialNumber);
    }

    /**
     * Get serial number.
     *
     * @throws \LogicException If not set
     *
     * @return string Base 10 integer
     */
    public function serialNumber(): string
    {
        if (!$this->hasSerialNumber()) {
            throw new \LogicException('serialNumber not set.');
        }
        return $this->_serialNumber;
    }

    /**
     * Check whether signature algorithm is set.
     *
     * @return bool
     */
    public function hasSignature(): bool
    {
        return isset($this->_signature);
    }

    /**
     * Get signature algorithm.
     *
     * @throws \LogicException If not set
     *
     * @return SignatureAlgorithmIdentifier
     */
    public function signature(): SignatureAlgorithmIdentifier
    {
        if (!$this->hasSignature()) {
            throw new \LogicException('signature not set.');
        }
        return $this->_signature;
    }

    /**
     * Get issuer.
     *
     * @return Name
     */
    public function issuer(): Name
    {
        return $this->_issuer;
    }

    /**
     * Get validity period.
     *
     * @return Validity
     */
    public function validity(): Validity
    {
        return $this->_validity;
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
     * Get subject public key.
     *
     * @return PublicKeyInfo
     */
    public function subjectPublicKeyInfo(): PublicKeyInfo
    {
        return $this->_subjectPublicKeyInfo;
    }

    /**
     * Whether issuer unique identifier is present.
     *
     * @return bool
     */
    public function hasIssuerUniqueID(): bool
    {
        return isset($this->_issuerUniqueID);
    }

    /**
     * Get issuerUniqueID.
     *
     * @throws \LogicException If not set
     *
     * @return UniqueIdentifier
     */
    public function issuerUniqueID(): UniqueIdentifier
    {
        if (!$this->hasIssuerUniqueID()) {
            throw new \LogicException('issuerUniqueID not set.');
        }
        return $this->_issuerUniqueID;
    }

    /**
     * Whether subject unique identifier is present.
     *
     * @return bool
     */
    public function hasSubjectUniqueID(): bool
    {
        return isset($this->_subjectUniqueID);
    }

    /**
     * Get subjectUniqueID.
     *
     * @throws \LogicException If not set
     *
     * @return UniqueIdentifier
     */
    public function subjectUniqueID(): UniqueIdentifier
    {
        if (!$this->hasSubjectUniqueID()) {
            throw new \LogicException('subjectUniqueID not set.');
        }
        return $this->_subjectUniqueID;
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
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = [];
        $version = $this->version();
        // if version is not default
        if (self::VERSION_1 != $version) {
            $elements[] = new ExplicitlyTaggedType(0, new Integer($version));
        }
        $serial = $this->serialNumber();
        $signature = $this->signature();
        // add required elements
        array_push($elements, new Integer($serial), $signature->toASN1(),
            $this->_issuer->toASN1(), $this->_validity->toASN1(),
            $this->_subject->toASN1(), $this->_subjectPublicKeyInfo->toASN1());
        if (isset($this->_issuerUniqueID)) {
            $elements[] = new ImplicitlyTaggedType(1,
                $this->_issuerUniqueID->toASN1());
        }
        if (isset($this->_subjectUniqueID)) {
            $elements[] = new ImplicitlyTaggedType(2,
                $this->_subjectUniqueID->toASN1());
        }
        if (count($this->_extensions)) {
            $elements[] = new ExplicitlyTaggedType(3,
                $this->_extensions->toASN1());
        }
        return new Sequence(...$elements);
    }

    /**
     * Create signed certificate.
     *
     * @param SignatureAlgorithmIdentifier $algo         Algorithm used for signing
     * @param PrivateKeyInfo               $privkey_info Private key used for signing
     * @param null|Crypto                  $crypto       Crypto engine, use default if not set
     *
     * @return Certificate
     */
    public function sign(SignatureAlgorithmIdentifier $algo,
        PrivateKeyInfo $privkey_info, ?Crypto $crypto = null): Certificate
    {
        $crypto = $crypto ?? Crypto::getDefault();
        $tbs_cert = clone $this;
        if (!isset($tbs_cert->_version)) {
            $tbs_cert->_version = $tbs_cert->_determineVersion();
        }
        if (!isset($tbs_cert->_serialNumber)) {
            $tbs_cert->_serialNumber = strval(0);
        }
        $tbs_cert->_signature = $algo;
        $data = $tbs_cert->toASN1()->toDER();
        $signature = $crypto->sign($data, $privkey_info, $algo);
        return new Certificate($tbs_cert, $algo, $signature);
    }

    /**
     * Determine minimum version for the certificate.
     *
     * @return int
     */
    protected function _determineVersion(): int
    {
        // if extensions are present
        if (count($this->_extensions)) {
            return self::VERSION_3;
        }
        // if UniqueIdentifier is present
        if (isset($this->_issuerUniqueID) || isset($this->_subjectUniqueID)) {
            return self::VERSION_2;
        }
        return self::VERSION_1;
    }
}
