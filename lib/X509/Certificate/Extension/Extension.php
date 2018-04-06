<?php
declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\DERData;
use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Boolean;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;

/**
 * Base class for certificate extensions.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2
 * @link https://tools.ietf.org/html/rfc5280#section-4.1
 */
abstract class Extension
{
    // OID's from standard certificate extensions
    const OID_OBSOLETE_AUTHORITY_KEY_IDENTIFIER = "2.5.29.1";
    const OID_OBSOLETE_KEY_ATTRIBUTES = "2.5.29.2";
    const OID_OBSOLETE_CERTIFICATE_POLICIES = "2.5.29.3";
    const OID_OBSOLETE_KEY_USAGE_RESTRICTION = "2.5.29.4";
    const OID_OBSOLETE_POLICY_MAPPING = "2.5.29.5";
    const OID_OBSOLETE_SUBTREES_CONSTRAINT = "2.5.29.6";
    const OID_OBSOLETE_SUBJECT_ALT_NAME = "2.5.29.7";
    const OID_OBSOLETE_ISSUER_ALT_NAME = "2.5.29.8";
    const OID_SUBJECT_DIRECTORY_ATTRIBUTES = "2.5.29.9";
    const OID_OBSOLETE_BASIC_CONSTRAINTS = "2.5.29.10";
    const OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    const OID_KEY_USAGE = "2.5.29.15";
    const OID_PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";
    const OID_SUBJECT_ALT_NAME = "2.5.29.17";
    const OID_ISSUER_ALT_NAME = "2.5.29.18";
    const OID_BASIC_CONSTRAINTS = "2.5.29.19";
    const OID_CRL_NUMBER = "2.5.29.20";
    const OID_REASON_CODE = "2.5.29.21";
    const OID_OBSOLETE_EXPIRATION_DATE = "2.5.29.22";
    const OID_INSTRUCTION_CODE = "2.5.29.23";
    const OID_INVALIDITY_DATE = "2.5.29.24";
    const OID_OBSOLETE_CRL_DISTRIBUTION_POINTS = "2.5.29.25";
    const OID_OBSOLETE_ISSUING_DISTRIBUTION_POINT = "2.5.29.26";
    const OID_DELTA_CRL_INDICATOR = "2.5.29.27";
    const OID_ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
    const OID_CERTIFICATE_ISSUER = "2.5.29.29";
    const OID_NAME_CONSTRAINTS = "2.5.29.30";
    const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    const OID_CERTIFICATE_POLICIES = "2.5.29.32";
    const OID_POLICY_MAPPINGS = "2.5.29.33";
    const OID_OBSOLETE_POLICY_CONSTRAINTS = "2.5.29.34";
    const OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    const OID_POLICY_CONSTRAINTS = "2.5.29.36";
    const OID_EXT_KEY_USAGE = "2.5.29.37";
    const OID_AUTHORITY_ATTRIBUTE_IDENTIFIER = "2.5.29.38";
    const OID_ROLE_SPEC_CERT_IDENTIFIER = "2.5.29.39";
    const OID_CRL_STREAM_IDENTIFIER = "2.5.29.40";
    const OID_BASIC_ATT_CONSTRAINTS = "2.5.29.41";
    const OID_DELEGATED_NAME_CONSTRAINTS = "2.5.29.42";
    const OID_TIME_SPECIFICATION = "2.5.29.43";
    const OID_CRL_SCOPE = "2.5.29.44";
    const OID_STATUS_REFERRALS = "2.5.29.45";
    const OID_FRESHEST_CRL = "2.5.29.46";
    const OID_ORDERED_LIST = "2.5.29.47";
    const OID_ATTRIBUTE_DESCRIPTOR = "2.5.29.48";
    const OID_USER_NOTICE = "2.5.29.49";
    const OID_SOA_IDENTIFIER = "2.5.29.50";
    const OID_BASE_UPDATE_TIME = "2.5.29.51";
    const OID_ACCEPTABLE_CERT_POLICIES = "2.5.29.52";
    const OID_DELTA_INFO = "2.5.29.53";
    const OID_INHIBIT_ANY_POLICY = "2.5.29.54";
    const OID_TARGET_INFORMATION = "2.5.29.55";
    const OID_NO_REV_AVAIL = "2.5.29.56";
    const OID_ACCEPTABLE_PRIVILEGE_POLICIES = "2.5.29.57";
    const OID_TO_BE_REVOKED = "2.5.29.58";
    const OID_REVOKED_GROUPS = "2.5.29.59";
    const OID_EXPIRED_CERTS_ON_CRL = "2.5.29.60";
    const OID_INDIRECT_ISSUER = "2.5.29.61";
    const OID_NO_ASSERTION = "2.5.29.62";
    const OID_AA_ISSUING_DISTRIBUTION_POINT = "2.5.29.63";
    const OID_ISSUED_ON_BEHALF_OF = "2.5.29.64";
    const OID_SINGLE_USE = "2.5.29.65";
    const OID_GROUP_AC = "2.5.29.66";
    const OID_ALLOWED_ATT_ASS = "2.5.29.67";
    const OID_ATTRIBUTE_MAPPINGS = "2.5.29.68";
    const OID_HOLDER_NAME_CONSTRAINTS = "2.5.29.69";
    
    // OID's from private certificate extensions arc
    const OID_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";
    const OID_AA_CONTROLS = "1.3.6.1.5.5.7.1.6";
    const OID_SUBJECT_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.11";
    const OID_LOGOTYPE = "1.3.6.1.5.5.7.1.12";
    
    /**
     * Mapping from extension ID to implementation class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_OID_TO_CLASS = array(
        /* @formatter:off */
        self::OID_AUTHORITY_KEY_IDENTIFIER => AuthorityKeyIdentifierExtension::class,
        self::OID_SUBJECT_KEY_IDENTIFIER => SubjectKeyIdentifierExtension::class,
        self::OID_KEY_USAGE => KeyUsageExtension::class,
        self::OID_CERTIFICATE_POLICIES => CertificatePoliciesExtension::class,
        self::OID_POLICY_MAPPINGS => PolicyMappingsExtension::class,
        self::OID_SUBJECT_ALT_NAME => SubjectAlternativeNameExtension::class,
        self::OID_ISSUER_ALT_NAME => IssuerAlternativeNameExtension::class,
        self::OID_SUBJECT_DIRECTORY_ATTRIBUTES => SubjectDirectoryAttributesExtension::class,
        self::OID_BASIC_CONSTRAINTS => BasicConstraintsExtension::class,
        self::OID_NAME_CONSTRAINTS => NameConstraintsExtension::class,
        self::OID_POLICY_CONSTRAINTS => PolicyConstraintsExtension::class,
        self::OID_EXT_KEY_USAGE => ExtendedKeyUsageExtension::class,
        self::OID_CRL_DISTRIBUTION_POINTS => CRLDistributionPointsExtension::class,
        self::OID_INHIBIT_ANY_POLICY => InhibitAnyPolicyExtension::class,
        self::OID_FRESHEST_CRL => FreshestCRLExtension::class,
        self::OID_NO_REV_AVAIL => NoRevocationAvailableExtension::class,
        self::OID_TARGET_INFORMATION => TargetInformationExtension::class,
        self::OID_AA_CONTROLS => AAControlsExtension::class
        /* @formatter:on */
    );
    
    /**
     * Mapping from extensions ID to short name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_OID_TO_NAME = array(
        /* @formatter:off */
        self::OID_AUTHORITY_KEY_IDENTIFIER => "authorityKeyIdentifier",
        self::OID_SUBJECT_KEY_IDENTIFIER => "subjectKeyIdentifier",
        self::OID_KEY_USAGE => "keyUsage",
        self::OID_PRIVATE_KEY_USAGE_PERIOD => "privateKeyUsagePeriod",
        self::OID_CERTIFICATE_POLICIES => "certificatePolicies",
        self::OID_POLICY_MAPPINGS => "policyMappings",
        self::OID_SUBJECT_ALT_NAME => "subjectAltName",
        self::OID_ISSUER_ALT_NAME => "issuerAltName",
        self::OID_SUBJECT_DIRECTORY_ATTRIBUTES => "subjectDirectoryAttributes",
        self::OID_BASIC_CONSTRAINTS => "basicConstraints",
        self::OID_NAME_CONSTRAINTS => "nameConstraints",
        self::OID_POLICY_CONSTRAINTS => "policyConstraints",
        self::OID_EXT_KEY_USAGE => "extKeyUsage",
        self::OID_CRL_DISTRIBUTION_POINTS => "cRLDistributionPoints",
        self::OID_INHIBIT_ANY_POLICY => "inhibitAnyPolicy",
        self::OID_FRESHEST_CRL => "freshestCRL",
        self::OID_NO_REV_AVAIL => "noRevAvail",
        self::OID_TARGET_INFORMATION => "targetInformation",
        self::OID_AUTHORITY_INFORMATION_ACCESS => "authorityInfoAccess",
        self::OID_AA_CONTROLS => "aaControls",
        self::OID_SUBJECT_INFORMATION_ACCESS => "subjectInfoAccess",
        self::OID_LOGOTYPE => "logotype"
        /* @formatter:on */
    );
    
    /**
     * Extension's OID.
     *
     * @var string $_oid
     */
    protected $_oid;
    
    /**
     * Whether extension is critical.
     *
     * @var bool $_critical
     */
    protected $_critical;
    
    /**
     * Get ASN.1 structure of the extension value.
     *
     * @return Element
     */
    abstract protected function _valueASN1();
    
    /**
     * Parse extension value from DER.
     *
     * @param string $data DER data
     * @param bool $critical Whether extension is critical
     * @throws \BadMethodCallException
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical)
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . " must be implemented in derived class.");
    }
    
    /**
     * Constructor.
     *
     * @param string $oid Extension OID
     * @param bool $critical Whether extension is critical
     */
    public function __construct(string $oid, bool $critical)
    {
        $this->_oid = $oid;
        $this->_critical = $critical;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq): Extension
    {
        $extnID = $seq->at(0)
            ->asObjectIdentifier()
            ->oid();
        $critical = false;
        $idx = 1;
        if ($seq->has($idx, Element::TYPE_BOOLEAN)) {
            $critical = $seq->at($idx++)
                ->asBoolean()
                ->value();
        }
        $data = $seq->at($idx)
            ->asOctetString()
            ->string();
        if (array_key_exists($extnID, self::MAP_OID_TO_CLASS)) {
            $cls = self::MAP_OID_TO_CLASS[$extnID];
            return $cls::_fromDER($data, $critical);
        }
        return new UnknownExtension($extnID, $critical, new DERData($data));
    }
    
    /**
     * Get extension OID.
     *
     * @return string
     */
    public function oid(): string
    {
        return $this->_oid;
    }
    
    /**
     * Check whether extension is critical.
     *
     * @return bool
     */
    public function isCritical(): bool
    {
        return $this->_critical;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array(new ObjectIdentifier($this->_oid));
        if ($this->_critical) {
            $elements[] = new Boolean(true);
        }
        $elements[] = new OctetString($this->_valueASN1()->toDER());
        return new Sequence(...$elements);
    }
    
    /**
     * Get short name of the extension.
     *
     * @return string
     */
    public function extensionName(): string
    {
        if (array_key_exists($this->_oid, self::MAP_OID_TO_NAME)) {
            return self::MAP_OID_TO_NAME[$this->_oid];
        }
        return $this->oid();
    }
    
    /**
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->extensionName();
    }
}
