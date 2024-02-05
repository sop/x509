<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationPath\PathValidation;

use Sop\ASN1\Element;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\Policy\PolicyNode;
use Sop\X509\CertificationPath\Policy\PolicyTree;

/**
 * State class for the certification path validation process.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.1
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.2
 */
class ValidatorState
{
    /**
     * Length of the certification path (n).
     *
     * @var int
     */
    protected $_pathLength;

    /**
     * Current index in the certification path in the range of 1..n (i).
     *
     * @var int
     */
    protected $_index;

    /**
     * Valid policy tree (valid_policy_tree).
     *
     * A tree of certificate policies with their optional qualifiers.
     * Each of the leaves of the tree represents a valid policy at this stage in
     * the certification path validation.
     * Once the tree is set to NULL, policy processing ceases.
     *
     * @var null|PolicyTree
     */
    protected $_validPolicyTree;

    /**
     * Permitted subtrees (permitted_subtrees).
     *
     * A set of root names for each name type defining a set of subtrees within
     * which all subject names in subsequent certificates in the certification
     * path must fall.
     *
     * @var mixed
     */
    protected $_permittedSubtrees;

    /**
     * Excluded subtrees (excluded_subtrees).
     *
     * A set of root names for each name type defining a set of subtrees within
     * which no subject name in subsequent certificates in the certification
     * path may fall.
     *
     * @var mixed
     */
    protected $_excludedSubtrees;

    /**
     * Explicit policy (explicit_policy).
     *
     * An integer that indicates if a non-NULL valid_policy_tree is required.
     *
     * @var int
     */
    protected $_explicitPolicy;

    /**
     * Inhibit anyPolicy (inhibit_anyPolicy).
     *
     * An integer that indicates whether the anyPolicy policy identifier is
     * considered a match.
     *
     * @var int
     */
    protected $_inhibitAnyPolicy;

    /**
     * Policy mapping (policy_mapping).
     *
     * An integer that indicates if policy mapping is permitted.
     *
     * @var int
     */
    protected $_policyMapping;

    /**
     * Working public key algorithm (working_public_key_algorithm).
     *
     * The digital signature algorithm used to verify the signature of a
     * certificate.
     *
     * @var AlgorithmIdentifierType
     */
    protected $_workingPublicKeyAlgorithm;

    /**
     * Working public key (working_public_key).
     *
     * The public key used to verify the signature of a certificate.
     *
     * @var PublicKeyInfo
     */
    protected $_workingPublicKey;

    /**
     * Working public key parameters (working_public_key_parameters).
     *
     * Parameters associated with the current public key that may be required to
     * verify a signature.
     *
     * @var null|Element
     */
    protected $_workingPublicKeyParameters;

    /**
     * Working issuer name (working_issuer_name).
     *
     * The issuer distinguished name expected in the next certificate in the
     * chain.
     *
     * @var Name
     */
    protected $_workingIssuerName;

    /**
     * Maximum certification path length (max_path_length).
     *
     * @var int
     */
    protected $_maxPathLength;

    /**
     * Constructor.
     */
    protected function __construct() {}

    /**
     * Initialize variables according to RFC 5280 6.1.2.
     *
     * @see https://tools.ietf.org/html/rfc5280#section-6.1.2
     *
     * @param Certificate $trust_anchor Trust anchor certificate
     * @param int         $n            Number of certificates
     *                                  in the certification path
     */
    public static function initialize(PathValidationConfig $config,
        Certificate $trust_anchor, int $n): self
    {
        $state = new self();
        $state->_pathLength = $n;
        $state->_index = 1;
        $state->_validPolicyTree = new PolicyTree(PolicyNode::anyPolicyNode());
        $state->_permittedSubtrees = null;
        $state->_excludedSubtrees = null;
        $state->_explicitPolicy = $config->explicitPolicy() ? 0 : $n + 1;
        $state->_inhibitAnyPolicy = $config->anyPolicyInhibit() ? 0 : $n + 1;
        $state->_policyMapping = $config->policyMappingInhibit() ? 0 : $n + 1;
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
     * Get self with current certification path index set.
     */
    public function withIndex(int $index): self
    {
        $state = clone $this;
        $state->_index = $index;
        return $state;
    }

    /**
     * Get self with valid_policy_tree.
     */
    public function withValidPolicyTree(PolicyTree $policy_tree): self
    {
        $state = clone $this;
        $state->_validPolicyTree = $policy_tree;
        return $state;
    }

    /**
     * Get self with valid_policy_tree set to null.
     */
    public function withoutValidPolicyTree(): self
    {
        $state = clone $this;
        $state->_validPolicyTree = null;
        return $state;
    }

    /**
     * Get self with explicit_policy.
     */
    public function withExplicitPolicy(int $num): self
    {
        $state = clone $this;
        $state->_explicitPolicy = $num;
        return $state;
    }

    /**
     * Get self with inhibit_anyPolicy.
     */
    public function withInhibitAnyPolicy(int $num): self
    {
        $state = clone $this;
        $state->_inhibitAnyPolicy = $num;
        return $state;
    }

    /**
     * Get self with policy_mapping.
     */
    public function withPolicyMapping(int $num): self
    {
        $state = clone $this;
        $state->_policyMapping = $num;
        return $state;
    }

    /**
     * Get self with working_public_key_algorithm.
     */
    public function withWorkingPublicKeyAlgorithm(AlgorithmIdentifierType $algo): self
    {
        $state = clone $this;
        $state->_workingPublicKeyAlgorithm = $algo;
        return $state;
    }

    /**
     * Get self with working_public_key.
     */
    public function withWorkingPublicKey(PublicKeyInfo $pubkey_info): self
    {
        $state = clone $this;
        $state->_workingPublicKey = $pubkey_info;
        return $state;
    }

    /**
     * Get self with working_public_key_parameters.
     */
    public function withWorkingPublicKeyParameters(?Element $params = null): self
    {
        $state = clone $this;
        $state->_workingPublicKeyParameters = $params;
        return $state;
    }

    /**
     * Get self with working_issuer_name.
     */
    public function withWorkingIssuerName(Name $issuer): self
    {
        $state = clone $this;
        $state->_workingIssuerName = $issuer;
        return $state;
    }

    /**
     * Get self with max_path_length.
     */
    public function withMaxPathLength(int $length): self
    {
        $state = clone $this;
        $state->_maxPathLength = $length;
        return $state;
    }

    /**
     * Get the certification path length (n).
     */
    public function pathLength(): int
    {
        return $this->_pathLength;
    }

    /**
     * Get the current index in certification path in the range of 1..n.
     */
    public function index(): int
    {
        return $this->_index;
    }

    /**
     * Check whether valid_policy_tree is present.
     */
    public function hasValidPolicyTree(): bool
    {
        return isset($this->_validPolicyTree);
    }

    /**
     * Get valid_policy_tree.
     *
     * @throws \LogicException If not set
     */
    public function validPolicyTree(): PolicyTree
    {
        if (!$this->hasValidPolicyTree()) {
            throw new \LogicException('valid_policy_tree not set.');
        }
        return $this->_validPolicyTree;
    }

    /**
     * Get permitted_subtrees.
     *
     * @return mixed
     */
    public function permittedSubtrees()
    {
        return $this->_permittedSubtrees;
    }

    /**
     * Get excluded_subtrees.
     *
     * @return mixed
     */
    public function excludedSubtrees()
    {
        return $this->_excludedSubtrees;
    }

    /**
     * Get explicit_policy.
     */
    public function explicitPolicy(): int
    {
        return $this->_explicitPolicy;
    }

    /**
     * Get inhibit_anyPolicy.
     */
    public function inhibitAnyPolicy(): int
    {
        return $this->_inhibitAnyPolicy;
    }

    /**
     * Get policy_mapping.
     */
    public function policyMapping(): int
    {
        return $this->_policyMapping;
    }

    /**
     * Get working_public_key_algorithm.
     */
    public function workingPublicKeyAlgorithm(): AlgorithmIdentifierType
    {
        return $this->_workingPublicKeyAlgorithm;
    }

    /**
     * Get working_public_key.
     */
    public function workingPublicKey(): PublicKeyInfo
    {
        return $this->_workingPublicKey;
    }

    /**
     * Get working_public_key_parameters.
     */
    public function workingPublicKeyParameters(): ?Element
    {
        return $this->_workingPublicKeyParameters;
    }

    /**
     * Get working_issuer_name.
     */
    public function workingIssuerName(): Name
    {
        return $this->_workingIssuerName;
    }

    /**
     * Get maximum certification path length.
     */
    public function maxPathLength(): int
    {
        return $this->_maxPathLength;
    }

    /**
     * Check whether processing the final certificate of the certification path.
     */
    public function isFinal(): bool
    {
        return $this->_index === $this->_pathLength;
    }

    /**
     * Get the path validation result.
     *
     * @param Certificate[] $certificates Certificates in a certification path
     */
    public function getResult(array $certificates): PathValidationResult
    {
        return new PathValidationResult($certificates, $this->_validPolicyTree,
            $this->_workingPublicKey, $this->_workingPublicKeyAlgorithm,
            $this->_workingPublicKeyParameters);
    }

    /**
     * Get ASN.1 parameters from algorithm identifier.
     *
     * @return null|Element ASN.1 element or null if parameters are omitted
     */
    public static function getAlgorithmParameters(AlgorithmIdentifierType $algo): ?Element
    {
        $seq = $algo->toASN1();
        return $seq->has(1) ? $seq->at(1)->asElement() : null;
    }
}
