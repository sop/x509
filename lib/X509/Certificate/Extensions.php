<?php

declare(strict_types = 1);

namespace X509\Certificate;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension as Ext;

/**
 * Implements <i>Extensions</i> ASN.1 type.
 *
 * Several convenience methods are provided to fetch commonly used
 * standard extensions. Others can be accessed using <code>get($oid)</code>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1.2.9
 */
class Extensions implements \Countable, \IteratorAggregate
{
    /**
     * Extensions.
     *
     * @var Extension\Extension[] $_extensions
     */
    protected $_extensions;
    
    /**
     * Constructor.
     *
     * @param Extension\Extension[] ...$extensions Extension objects
     */
    public function __construct(Ext\Extension ...$extensions)
    {
        $this->_extensions = array();
        foreach ($extensions as $ext) {
            $this->_extensions[$ext->oid()] = $ext;
        }
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $extensions = array_map(
            function (UnspecifiedType $el) {
                return Ext\Extension::fromASN1($el->asSequence());
            }, $seq->elements());
        return new self(...$extensions);
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array_values(
            array_map(
                function ($ext) {
                    return $ext->toASN1();
                }, $this->_extensions));
        return new Sequence(...$elements);
    }
    
    /**
     * Get self with extensions added.
     *
     * @param Extension\Extension ...$ext One or more extensions to add
     * @return self
     */
    public function withExtensions(Ext\Extension ...$exts): self
    {
        $obj = clone $this;
        foreach ($exts as $ext) {
            $obj->_extensions[$ext->oid()] = $ext;
        }
        return $obj;
    }
    
    /**
     * Check whether extension is present.
     *
     * @param string $oid Extensions OID
     * @return bool
     */
    public function has(string $oid): bool
    {
        return isset($this->_extensions[$oid]);
    }
    
    /**
     * Get extension by OID.
     *
     * @param string $oid
     * @throws \LogicException If extension is not present
     * @return Extension\Extension
     */
    public function get(string $oid): Ext\Extension
    {
        if (!$this->has($oid)) {
            throw new \LogicException("No extension by OID $oid.");
        }
        return $this->_extensions[$oid];
    }
    
    /**
     * Check whether 'Authority Key Identifier' extension is present.
     *
     * @return bool
     */
    public function hasAuthorityKeyIdentifier(): bool
    {
        return $this->has(Ext\Extension::OID_AUTHORITY_KEY_IDENTIFIER);
    }
    
    /**
     * Get 'Authority Key Identifier' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\AuthorityKeyIdentifierExtension
     */
    public function authorityKeyIdentifier(): Ext\AuthorityKeyIdentifierExtension
    {
        /** @var Extension\AuthorityKeyIdentifierExtension $keyIdentifier */
        $keyIdentifier = $this->get(Ext\Extension::OID_AUTHORITY_KEY_IDENTIFIER);
        return $keyIdentifier;
    }
    
    /**
     * Check whether 'Subject Key Identifier' extension is present.
     *
     * @return bool
     */
    public function hasSubjectKeyIdentifier(): bool
    {
        return $this->has(Ext\Extension::OID_SUBJECT_KEY_IDENTIFIER);
    }
    
    /**
     * Get 'Subject Key Identifier' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\SubjectKeyIdentifierExtension
     */
    public function subjectKeyIdentifier(): Ext\SubjectKeyIdentifierExtension
    {
        /** @var Extension\SubjectKeyIdentifierExtension $subjectKeyIdentifier */
        $subjectKeyIdentifier = $this->get(
            Ext\Extension::OID_SUBJECT_KEY_IDENTIFIER);
        return $subjectKeyIdentifier;
    }
    
    /**
     * Check whether 'Key Usage' extension is present.
     *
     * @return bool
     */
    public function hasKeyUsage(): bool
    {
        return $this->has(Ext\Extension::OID_KEY_USAGE);
    }
    
    /**
     * Get 'Key Usage' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\KeyUsageExtension
     */
    public function keyUsage(): Ext\KeyUsageExtension
    {
        /** @var Extension\KeyUsageExtension $keyUsage */
        $keyUsage = $this->get(Ext\Extension::OID_KEY_USAGE);
        return $keyUsage;
    }
    
    /**
     * Check whether 'Certificate Policies' extension is present.
     *
     * @return bool
     */
    public function hasCertificatePolicies(): bool
    {
        return $this->has(Ext\Extension::OID_CERTIFICATE_POLICIES);
    }
    
    /**
     * Get 'Certificate Policies' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\CertificatePoliciesExtension
     */
    public function certificatePolicies(): Ext\CertificatePoliciesExtension
    {
        /** @var Extension\CertificatePoliciesExtension $certPolicies */
        $certPolicies = $this->get(Ext\Extension::OID_CERTIFICATE_POLICIES);
        return $certPolicies;
    }
    
    /**
     * Check whether 'Policy Mappings' extension is present.
     *
     * @return bool
     */
    public function hasPolicyMappings(): bool
    {
        return $this->has(Ext\Extension::OID_POLICY_MAPPINGS);
    }
    
    /**
     * Get 'Policy Mappings' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\PolicyMappingsExtension
     */
    public function policyMappings(): Ext\PolicyMappingsExtension
    {
        /** @var Extension\PolicyMappingsExtension $policyMappings */
        $policyMappings = $this->get(Ext\Extension::OID_POLICY_MAPPINGS);
        return $policyMappings;
    }
    
    /**
     * Check whether 'Subject Alternative Name' extension is present.
     *
     * @return bool
     */
    public function hasSubjectAlternativeName(): bool
    {
        return $this->has(Ext\Extension::OID_SUBJECT_ALT_NAME);
    }
    
    /**
     * Get 'Subject Alternative Name' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\SubjectAlternativeNameExtension
     */
    public function subjectAlternativeName(): Ext\SubjectAlternativeNameExtension
    {
        /** @var Extension\SubjectAlternativeNameExtension $subjectAltName */
        $subjectAltName = $this->get(Ext\Extension::OID_SUBJECT_ALT_NAME);
        return $subjectAltName;
    }
    
    /**
     * Check whether 'Issuer Alternative Name' extension is present.
     *
     * @return bool
     */
    public function hasIssuerAlternativeName(): bool
    {
        return $this->has(Ext\Extension::OID_ISSUER_ALT_NAME);
    }
    
    /**
     * Get 'Issuer Alternative Name' extension.
     *
     * @return \X509\Certificate\Extension\IssuerAlternativeNameExtension
     */
    public function issuerAlternativeName(): Ext\IssuerAlternativeNameExtension
    {
        /** @var Extension\IssuerAlternativeNameExtension $issuerAltName */
        $issuerAltName = $this->get(Ext\Extension::OID_ISSUER_ALT_NAME);
        return $issuerAltName;
    }
    
    /**
     * Check whether 'Basic Constraints' extension is present.
     *
     * @return bool
     */
    public function hasBasicConstraints(): bool
    {
        return $this->has(Ext\Extension::OID_BASIC_CONSTRAINTS);
    }
    
    /**
     * Get 'Basic Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\BasicConstraintsExtension
     */
    public function basicConstraints(): Ext\BasicConstraintsExtension
    {
        /** @var Extension\BasicConstraintsExtension $basicConstraints */
        $basicConstraints = $this->get(Ext\Extension::OID_BASIC_CONSTRAINTS);
        return $basicConstraints;
    }
    
    /**
     * Check whether 'Name Constraints' extension is present.
     *
     * @return bool
     */
    public function hasNameConstraints(): bool
    {
        return $this->has(Ext\Extension::OID_NAME_CONSTRAINTS);
    }
    
    /**
     * Get 'Name Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\NameConstraintsExtension
     */
    public function nameConstraints(): Ext\NameConstraintsExtension
    {
        /** @var Extension\NameConstraintsExtension $nameConstraints */
        $nameConstraints = $this->get(Ext\Extension::OID_NAME_CONSTRAINTS);
        return $nameConstraints;
    }
    
    /**
     * Check whether 'Policy Constraints' extension is present.
     *
     * @return bool
     */
    public function hasPolicyConstraints(): bool
    {
        return $this->has(Ext\Extension::OID_POLICY_CONSTRAINTS);
    }
    
    /**
     * Get 'Policy Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\PolicyConstraintsExtension
     */
    public function policyConstraints(): Ext\PolicyConstraintsExtension
    {
        /** @var Extension\PolicyConstraintsExtension $policyConstraints */
        $policyConstraints = $this->get(Ext\Extension::OID_POLICY_CONSTRAINTS);
        return $policyConstraints;
    }
    
    /**
     * Check whether 'Extended Key Usage' extension is present.
     *
     * @return bool
     */
    public function hasExtendedKeyUsage(): bool
    {
        return $this->has(Ext\Extension::OID_EXT_KEY_USAGE);
    }
    
    /**
     * Get 'Extended Key Usage' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\ExtendedKeyUsageExtension
     */
    public function extendedKeyUsage(): Ext\ExtendedKeyUsageExtension
    {
        /** @var Extension\ExtendedKeyUsageExtension $keyUsage */
        $keyUsage = $this->get(Ext\Extension::OID_EXT_KEY_USAGE);
        return $keyUsage;
    }
    
    /**
     * Check whether 'CRL Distribution Points' extension is present.
     *
     * @return bool
     */
    public function hasCRLDistributionPoints(): bool
    {
        return $this->has(Ext\Extension::OID_CRL_DISTRIBUTION_POINTS);
    }
    
    /**
     * Get 'CRL Distribution Points' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\CRLDistributionPointsExtension
     */
    public function crlDistributionPoints(): Ext\CRLDistributionPointsExtension
    {
        /** @var Extension\CRLDistributionPointsExtension $crlDist */
        $crlDist = $this->get(Ext\Extension::OID_CRL_DISTRIBUTION_POINTS);
        return $crlDist;
    }
    
    /**
     * Check whether 'Inhibit anyPolicy' extension is present.
     *
     * @return bool
     */
    public function hasInhibitAnyPolicy(): bool
    {
        return $this->has(Ext\Extension::OID_INHIBIT_ANY_POLICY);
    }
    
    /**
     * Get 'Inhibit anyPolicy' extension.
     *
     * @throws \LogicException If extension is not present
     * @return \X509\Certificate\Extension\InhibitAnyPolicyExtension
     */
    public function inhibitAnyPolicy(): Ext\InhibitAnyPolicyExtension
    {
        /** @var Extension\InhibitAnyPolicyExtension $inhibitAny */
        $inhibitAny = $this->get(Ext\Extension::OID_INHIBIT_ANY_POLICY);
        return $inhibitAny;
    }
    
    /**
     *
     * @see \Countable::count()
     * @return int
     */
    public function count(): int
    {
        return count($this->_extensions);
    }
    
    /**
     * Get iterator for extensions.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \Traversable
     */
    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->_extensions);
    }
}
