<?php

namespace X509\CertificationPath\PathValidation;

use ASN1\Element;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use CryptoUtil\ASN1\PublicKeyInfo;
use X501\ASN1\Name;
use X509\Certificate\Certificate;
use X509\CertificationPath\Policy\PolicyNode;


/**
 * State class for the certification path validation process.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.1
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.2
 */
class ValidatorState
{
	/**
	 *
	 * @var mixed $_validPolicyTree
	 */
	protected $_validPolicyTree;
	
	/**
	 *
	 * @var mixed $_permittedSubtrees
	 */
	protected $_permittedSubtrees;
	
	/**
	 *
	 * @var mixed $_excludedSubtrees
	 */
	protected $_excludedSubtrees;
	
	/**
	 *
	 * @var int $_explicitPolicy
	 */
	protected $_explicitPolicy;
	
	/**
	 *
	 * @var int $_inhibitAnyPolicy
	 */
	protected $_inhibitAnyPolicy;
	
	/**
	 *
	 * @var int $_policyMapping
	 */
	protected $_policyMapping;
	
	/**
	 *
	 * @var AlgorithmIdentifierType $_workingPublicKeyAlgorithm
	 */
	protected $_workingPublicKeyAlgorithm;
	
	/**
	 *
	 * @var PublicKeyInfo $_workingPublicKey
	 */
	protected $_workingPublicKey;
	
	/**
	 *
	 * @var Element|null $_workingPublicKeyParameters
	 */
	protected $_workingPublicKeyParameters;
	
	/**
	 *
	 * @var Name $_workingIssuerName
	 */
	protected $_workingIssuerName;
	
	/**
	 *
	 * @var int $_maxPathLength
	 */
	protected $_maxPathLength;
	
	/**
	 *
	 * @var bool $_isFinalCertificate
	 */
	protected $_isFinalCertificate;
	
	/**
	 * Constructor
	 */
	protected function __constructor() {}
	
	/**
	 * Initialize variables according to RFC 5280 6.1.2.
	 *
	 * @link https://tools.ietf.org/html/rfc5280#section-6.1.2
	 * @param PathValidationConfig $config
	 * @param Certificate $trust_anchor Trust anchor certificate
	 * @param int $path_length Number of certificates in the certification path
	 * @return self
	 */
	public static function initialize(PathValidationConfig $config, 
			Certificate $trust_anchor, $path_length) {
		$state = new self();
		$state->_validPolicyTree = array(PolicyNode::anyPolicyNode());
		$state->_permittedSubtrees = null;
		$state->_excludedSubtrees = null;
		$state->_explicitPolicy = $config->explicitPolicy() ? 0 : $path_length +
			 1;
		$state->_inhibitAnyPolicy = $config->anyPolicyInhibit() ? 0 : $path_length +
			 1;
		$state->_policyMapping = $config->policyMappingInhibit() ? 0 : $path_length +
			 1;
		$state->_workingPublicKeyAlgorithm = $trust_anchor->signatureAlgorithm();
		$tbsCert = $trust_anchor->tbsCertificate();
		$state->_workingPublicKey = $tbsCert->subjectPublicKeyInfo();
		$state->_workingPublicKeyParameters = self::getAlgorithmParameters(
			$state->_workingPublicKey->algorithmIdentifier());
		$state->_workingIssuerName = $tbsCert->issuer();
		$state->_maxPathLength = $config->maxLength();
		return $state;
	}
	
	/**
	 * Get self with valid_policy_tree.
	 *
	 * @param mixed $policy_tree
	 * @return self
	 */
	public function withValidPolicyTree($policy_tree) {
		$state = clone $this;
		$state->_validPolicyTree = $policy_tree;
		return $state;
	}
	
	/**
	 * Get self with explicit_policy.
	 *
	 * @param int $num
	 * @return self
	 */
	public function withExplicitPolicy($num) {
		$state = clone $this;
		$state->_explicitPolicy = $num;
		return $state;
	}
	
	/**
	 * Get self with inhibit_anyPolicy.
	 *
	 * @param int $num
	 * @return self
	 */
	public function withInhibitAnyPolicy($num) {
		$state = clone $this;
		$state->_inhibitAnyPolicy = $num;
		return $state;
	}
	
	/**
	 * Get self with policy_mapping.
	 *
	 * @param int $num
	 * @return self
	 */
	public function withPolicyMapping($num) {
		$state = clone $this;
		$state->_policyMapping = $num;
		return $state;
	}
	
	/**
	 * Get self with working_public_key_algorithm.
	 *
	 * @param AlgorithmIdentifierType $algo
	 * @return self
	 */
	public function withWorkingPublicKeyAlgorithm(AlgorithmIdentifierType $algo) {
		$state = clone $this;
		$state->_workingPublicKeyAlgorithm = $algo;
		return $state;
	}
	
	/**
	 * Get self with working_public_key.
	 *
	 * @param PublicKeyInfo $pubkey_info
	 * @return self
	 */
	public function withWorkingPublicKey(PublicKeyInfo $pubkey_info) {
		$state = clone $this;
		$state->_workingPublicKey = $pubkey_info;
		return $state;
	}
	
	/**
	 * Get self with working_public_key_parameters.
	 *
	 * @param Element $params
	 * @return self
	 */
	public function withWorkingPublicKeyParameters(Element $params = null) {
		$state = clone $this;
		$state->_workingPublicKeyParameters = $params;
		return $state;
	}
	
	/**
	 * Get self with working_issuer_name.
	 *
	 * @param Name $issuer
	 * @return self
	 */
	public function withWorkingIssuerName(Name $issuer) {
		$state = clone $this;
		$state->_workingIssuerName = $issuer;
		return $state;
	}
	
	/**
	 * Get self with max_path_length.
	 *
	 * @param int $length
	 * @return self
	 */
	public function withMaxPathLength($length) {
		$state = clone $this;
		$state->_maxPathLength = $length;
		return $state;
	}
	
	/**
	 * Get self with final certificate flag.
	 *
	 * @param bool $is_final
	 * @return self
	 */
	public function withIsFinal($is_final) {
		$state = clone $this;
		$state->_isFinalCertificate = (bool) $is_final;
		return $state;
	}
	
	/**
	 * Check whether valid_policy_tree is present.
	 *
	 * @return bool
	 */
	public function hasValidPolicyTree() {
		return isset($this->_validPolicyTree);
	}
	
	/**
	 * Get valid_policy_tree.
	 *
	 * @return mixed
	 */
	public function validPolicyTree() {
		return $this->_validPolicyTree;
	}
	
	/**
	 * Get permitted_subtrees.
	 *
	 * @return mixed
	 */
	public function permittedSubtrees() {
		return $this->_permittedSubtrees;
	}
	
	/**
	 * Get excluded_subtrees.
	 *
	 * @return mixed
	 */
	public function excludedSubtrees() {
		return $this->_excludedSubtrees;
	}
	
	/**
	 * Get explicit_policy.
	 *
	 * @return int
	 */
	public function explicitPolicy() {
		return $this->_explicitPolicy;
	}
	
	/**
	 * Get inhibit_anyPolicy.
	 *
	 * @return int
	 */
	public function inhibitAnyPolicy() {
		return $this->_inhibitAnyPolicy;
	}
	
	/**
	 * Get policy_mapping.
	 *
	 * @return int
	 */
	public function policyMapping() {
		return $this->_policyMapping;
	}
	
	/**
	 * Get working_public_key_algorithm.
	 *
	 * @return AlgorithmIdentifierType
	 */
	public function workingPublicKeyAlgorithm() {
		return $this->_workingPublicKeyAlgorithm;
	}
	
	/**
	 * Get working_public_key.
	 *
	 * @return PublicKeyInfo
	 */
	public function workingPublicKey() {
		return $this->_workingPublicKey;
	}
	
	/**
	 * Get working_public_key_parameters.
	 *
	 * @return Element|null
	 */
	public function workingPublicKeyParameters() {
		return $this->_workingPublicKeyParameters;
	}
	
	/**
	 * Get working_issuer_name.
	 *
	 * @return Name
	 */
	public function workingIssuerName() {
		return $this->_workingIssuerName;
	}
	
	/**
	 * Get maximum certification path length.
	 *
	 * @return int
	 */
	public function maxPathLength() {
		return $this->_maxPathLength;
	}
	
	/**
	 * Check whether processing the final certificate of the certification path.
	 *
	 * @return bool
	 */
	public function isFinal() {
		return $this->_isFinalCertificate;
	}
	
	/**
	 * Get ASN.1 parameters from algorithm identifier.
	 *
	 * @param AlgorithmIdentifierType $algo
	 * @return Element|null ASN.1 element or null if parameters are omitted
	 */
	public static function getAlgorithmParameters(AlgorithmIdentifierType $algo) {
		$seq = $algo->toASN1();
		return $seq->has(1) ? $seq->at(1) : null;
	}
}
