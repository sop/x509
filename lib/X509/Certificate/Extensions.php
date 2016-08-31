<?php

namespace X509\Certificate;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\CertificatePoliciesExtension;
use X509\Certificate\Extension\CRLDistributionPointsExtension;
use X509\Certificate\Extension\ExtendedKeyUsageExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\InhibitAnyPolicyExtension;
use X509\Certificate\Extension\IssuerAlternativeNameExtension;
use X509\Certificate\Extension\KeyUsageExtension;
use X509\Certificate\Extension\NameConstraintsExtension;
use X509\Certificate\Extension\PolicyConstraintsExtension;
use X509\Certificate\Extension\PolicyMappingsExtension;
use X509\Certificate\Extension\SubjectAlternativeNameExtension;
use X509\Certificate\Extension\SubjectKeyIdentifierExtension;


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
	 * Extensions
	 *
	 * @var Extension[] $_extensions
	 */
	protected $_extensions;
	
	/**
	 * Constructor
	 *
	 * @param Extension ...$extensions Extension objects
	 */
	public function __construct(Extension ...$extensions) {
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
	public static function fromASN1(Sequence $seq) {
		$extensions = array_map(
			function (UnspecifiedType $el) {
				return Extension::fromASN1($el->asSequence());
			}, $seq->elements());
		return new self(...$extensions);
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array_values(
			array_map(function ($ext) {
				return $ext->toASN1();
			}, $this->_extensions));
		return new Sequence(...$elements);
	}
	
	/**
	 * Get self with extensions added.
	 *
	 * @param Extension ...$ext One or more extensions to add
	 * @return self
	 */
	public function withExtensions(Extension ...$exts) {
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
	public function has($oid) {
		return isset($this->_extensions[$oid]);
	}
	
	/**
	 * Get extension by OID.
	 *
	 * @param string $oid
	 * @throws \LogicException If extension is not present
	 * @return Extension
	 */
	public function get($oid) {
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
	public function hasAuthorityKeyIdentifier() {
		return $this->has(Extension::OID_AUTHORITY_KEY_IDENTIFIER);
	}
	
	/**
	 * Get 'Authority Key Identifier' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return AuthorityKeyIdentifierExtension
	 */
	public function authorityKeyIdentifier() {
		return $this->get(Extension::OID_AUTHORITY_KEY_IDENTIFIER);
	}
	
	/**
	 * Check whether 'Subject Key Identifier' extension is present.
	 *
	 * @return bool
	 */
	public function hasSubjectKeyIdentifier() {
		return $this->has(Extension::OID_SUBJECT_KEY_IDENTIFIER);
	}
	
	/**
	 * Get 'Subject Key Identifier' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return SubjectKeyIdentifierExtension
	 */
	public function subjectKeyIdentifier() {
		return $this->get(Extension::OID_SUBJECT_KEY_IDENTIFIER);
	}
	
	/**
	 * Check whether 'Key Usage' extension is present.
	 *
	 * @return bool
	 */
	public function hasKeyUsage() {
		return $this->has(Extension::OID_KEY_USAGE);
	}
	
	/**
	 * Get 'Key Usage' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return KeyUsageExtension
	 */
	public function keyUsage() {
		return $this->get(Extension::OID_KEY_USAGE);
	}
	
	/**
	 * Check whether 'Certificate Policies' extension is present.
	 *
	 * @return bool
	 */
	public function hasCertificatePolicies() {
		return $this->has(Extension::OID_CERTIFICATE_POLICIES);
	}
	
	/**
	 * Get 'Certificate Policies' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return CertificatePoliciesExtension
	 */
	public function certificatePolicies() {
		return $this->get(Extension::OID_CERTIFICATE_POLICIES);
	}
	
	/**
	 * Check whether 'Policy Mappings' extension is present.
	 *
	 * @return bool
	 */
	public function hasPolicyMappings() {
		return $this->has(Extension::OID_POLICY_MAPPINGS);
	}
	
	/**
	 * Get 'Policy Mappings' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return PolicyMappingsExtension
	 */
	public function policyMappings() {
		return $this->get(Extension::OID_POLICY_MAPPINGS);
	}
	
	/**
	 * Check whether 'Subject Alternative Name' extension is present.
	 *
	 * @return bool
	 */
	public function hasSubjectAlternativeName() {
		return $this->has(Extension::OID_SUBJECT_ALT_NAME);
	}
	
	/**
	 * Get 'Subject Alternative Name' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return SubjectAlternativeNameExtension
	 */
	public function subjectAlternativeName() {
		return $this->get(Extension::OID_SUBJECT_ALT_NAME);
	}
	
	/**
	 * Check whether 'Issuer Alternative Name' extension is present.
	 *
	 * @return bool
	 */
	public function hasIssuerAlternativeName() {
		return $this->has(Extension::OID_ISSUER_ALT_NAME);
	}
	
	/**
	 * Get 'Issuer Alternative Name' extension.
	 *
	 * @return IssuerAlternativeNameExtension
	 */
	public function issuerAlternativeName() {
		return $this->get(Extension::OID_ISSUER_ALT_NAME);
	}
	
	/**
	 * Check whether 'Basic Constraints' extension is present.
	 *
	 * @return bool
	 */
	public function hasBasicConstraints() {
		return $this->has(Extension::OID_BASIC_CONSTRAINTS);
	}
	
	/**
	 * Get 'Basic Constraints' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return BasicConstraintsExtension
	 */
	public function basicConstraints() {
		return $this->get(Extension::OID_BASIC_CONSTRAINTS);
	}
	
	/**
	 * Check whether 'Name Constraints' extension is present.
	 *
	 * @return bool
	 */
	public function hasNameConstraints() {
		return $this->has(Extension::OID_NAME_CONSTRAINTS);
	}
	
	/**
	 * Get 'Name Constraints' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return NameConstraintsExtension
	 */
	public function nameConstraints() {
		return $this->get(Extension::OID_NAME_CONSTRAINTS);
	}
	
	/**
	 * Check whether 'Policy Constraints' extension is present.
	 *
	 * @return bool
	 */
	public function hasPolicyConstraints() {
		return $this->has(Extension::OID_POLICY_CONSTRAINTS);
	}
	
	/**
	 * Get 'Policy Constraints' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return PolicyConstraintsExtension
	 */
	public function policyConstraints() {
		return $this->get(Extension::OID_POLICY_CONSTRAINTS);
	}
	
	/**
	 * Check whether 'Extended Key Usage' extension is present.
	 *
	 * @return bool
	 */
	public function hasExtendedKeyUsage() {
		return $this->has(Extension::OID_EXT_KEY_USAGE);
	}
	
	/**
	 * Get 'Extended Key Usage' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return ExtendedKeyUsageExtension
	 */
	public function extendedKeyUsage() {
		return $this->get(Extension::OID_EXT_KEY_USAGE);
	}
	
	/**
	 * Check whether 'CRL Distribution Points' extension is present.
	 *
	 * @return bool
	 */
	public function hasCRLDistributionPoints() {
		return $this->has(Extension::OID_CRL_DISTRIBUTION_POINTS);
	}
	
	/**
	 * Get 'CRL Distribution Points' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return CRLDistributionPointsExtension
	 */
	public function crlDistributionPoints() {
		return $this->get(Extension::OID_CRL_DISTRIBUTION_POINTS);
	}
	
	/**
	 * Check whether 'Inhibit anyPolicy' extension is present.
	 *
	 * @return bool
	 */
	public function hasInhibitAnyPolicy() {
		return $this->has(Extension::OID_INHIBIT_ANY_POLICY);
	}
	
	/**
	 * Get 'Inhibit anyPolicy' extension.
	 *
	 * @throws \LogicException If extension is not present
	 * @return InhibitAnyPolicyExtension
	 */
	public function inhibitAnyPolicy() {
		return $this->get(Extension::OID_INHIBIT_ANY_POLICY);
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_extensions);
	}
	
	/**
	 * Get iterator for extensions.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \Traversable
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_extensions);
	}
}
