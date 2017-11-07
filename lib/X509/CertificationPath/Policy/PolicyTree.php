<?php

declare(strict_types = 1);

namespace X509\CertificationPath\Policy;

use X509\Certificate\Certificate;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\CertificationPath\PathValidation\ValidatorState;

class PolicyTree
{
    /**
     * Root node at depth zero.
     *
     * @var PolicyNode|null
     */
    protected $_root;
    
    /**
     * Constructor.
     *
     * @param PolicyNode $root Initial root node
     */
    public function __construct(PolicyNode $root)
    {
        $this->_root = $root;
    }
    
    /**
     * Process policy information from the certificate.
     *
     * Certificate policies extension must be present.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    public function processPolicies(ValidatorState $state, Certificate $cert): ValidatorState
    {
        $policies = $cert->tbsCertificate()
            ->extensions()
            ->certificatePolicies();
        $tree = clone $this;
        // (d.1) for each policy P not equal to anyPolicy
        foreach ($policies as $policy) {
            if ($policy->isAnyPolicy()) {
                $tree->_processAnyPolicy($policy, $cert, $state);
            } else {
                $tree->_processPolicy($policy, $state);
            }
        }
        // if whole tree is pruned
        if (!$tree->_pruneTree($state->index() - 1)) {
            return $state->withoutValidPolicyTree();
        }
        return $state->withValidPolicyTree($tree);
    }
    
    /**
     * Process policy mappings from the certificate.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    public function processMappings(ValidatorState $state, Certificate $cert): ValidatorState
    {
        $tree = clone $this;
        if ($state->policyMapping() > 0) {
            $tree->_applyMappings($cert, $state);
        } else if ($state->policyMapping() == 0) {
            $tree->_deleteMappings($cert, $state);
        }
        // if whole tree is pruned
        if (!$tree->_root) {
            return $state->withoutValidPolicyTree();
        }
        return $state->withValidPolicyTree($tree);
    }
    
    /**
     * Calculate policy intersection as specified in Wrap-Up Procedure 6.1.5.g.
     *
     * @param ValidatorState $state
     * @param array $policies
     * @return ValidatorState
     */
    public function calculateIntersection(ValidatorState $state, array $policies): ValidatorState
    {
        $tree = clone $this;
        $valid_policy_node_set = $tree->_validPolicyNodeSet();
        // 2. If the valid_policy of any node in the valid_policy_node_set
        // is not in the user-initial-policy-set and is not anyPolicy,
        // delete this node and all its children.
        $valid_policy_node_set = array_filter($valid_policy_node_set,
            function (PolicyNode $node) use ($policies) {
                if ($node->isAnyPolicy()) {
                    return true;
                }
                if (in_array($node->validPolicy(), $policies)) {
                    return true;
                }
                $node->remove();
                return false;
            });
        // array of valid policy OIDs
        $valid_policy_set = array_map(
            function (PolicyNode $node) {
                return $node->validPolicy();
            }, $valid_policy_node_set);
        // 3. If the valid_policy_tree includes a node of depth n with
        // the valid_policy anyPolicy and the user-initial-policy-set 
        // is not any-policy
        foreach ($tree->_nodesAtDepth($state->index()) as $node) {
            if ($node->hasParent() && $node->isAnyPolicy()) {
                // a. Set P-Q to the qualifier_set in the node of depth n
                // with valid_policy anyPolicy.
                $pq = $node->qualifiers();
                // b. For each P-OID in the user-initial-policy-set that is not
                // the valid_policy of a node in the valid_policy_node_set,
                // create a child node whose parent is the node of depth n-1
                // with the valid_policy anyPolicy.
                $poids = array_diff($policies, $valid_policy_set);
                foreach ($tree->_nodesAtDepth($state->index() - 1) as $parent) {
                    if ($parent->isAnyPolicy()) {
                        // Set the values in the child node as follows: 
                        // set the valid_policy to P-OID, set the qualifier_set
                        // to P-Q, and set the expected_policy_set to {P-OID}.
                        foreach ($poids as $poid) {
                            $parent->addChild(
                                new PolicyNode($poid, $pq, array($poid)));
                        }
                        break;
                    }
                }
                // c. Delete the node of depth n with the
                // valid_policy anyPolicy.
                $node->remove();
            }
        }
        // 4. If there is a node in the valid_policy_tree of depth n-1 or less
        // without any child nodes, delete that node. Repeat this step until
        // there are no nodes of depth n-1 or less without children.
        if (!$tree->_pruneTree($state->index() - 1)) {
            return $state->withoutValidPolicyTree();
        }
        return $state->withValidPolicyTree($tree);
    }
    
    /**
     * Get policies at given policy tree depth.
     *
     * @param int $i Depth in range 1..n
     * @return PolicyInformation[]
     */
    public function policiesAtDepth(int $i): array
    {
        $policies = array();
        foreach ($this->_nodesAtDepth($i) as $node) {
            $policies[] = new PolicyInformation($node->validPolicy(),
                ...$node->qualifiers());
        }
        return $policies;
    }
    
    /**
     * Process single policy information.
     *
     * @param PolicyInformation $policy
     * @param ValidatorState $state
     */
    protected function _processPolicy(PolicyInformation $policy,
        ValidatorState $state)
    {
        $p_oid = $policy->oid();
        $i = $state->index();
        $match_count = 0;
        // (d.1.i) for each node of depth i-1 in the valid_policy_tree...
        foreach ($this->_nodesAtDepth($i - 1) as $node) {
            // ...where P-OID is in the expected_policy_set
            if ($node->hasExpectedPolicy($p_oid)) {
                $node->addChild(
                    new PolicyNode($p_oid, $policy->qualifiers(), array($p_oid)));
                ++$match_count;
            }
        }
        // (d.1.ii) if there was no match in step (i)...
        if (!$match_count) {
            // ...and the valid_policy_tree includes a node of depth i-1 with
            // the valid_policy anyPolicy
            foreach ($this->_nodesAtDepth($i - 1) as $node) {
                if ($node->isAnyPolicy()) {
                    $node->addChild(
                        new PolicyNode($p_oid, $policy->qualifiers(),
                            array($p_oid)));
                }
            }
        }
    }
    
    /**
     * Process anyPolicy policy information.
     *
     * @param PolicyInformation $policy
     * @param Certificate $cert
     * @param ValidatorState $state
     */
    protected function _processAnyPolicy(PolicyInformation $policy,
        Certificate $cert, ValidatorState $state)
    {
        $i = $state->index();
        // if (a) inhibit_anyPolicy is greater than 0 or
        // (b) i<n and the certificate is self-issued
        if (!($state->inhibitAnyPolicy() > 0 ||
             ($i < $state->pathLength() && $cert->isSelfIssued()))) {
            return;
        }
        // for each node in the valid_policy_tree of depth i-1
        foreach ($this->_nodesAtDepth($i - 1) as $node) {
            // for each value in the expected_policy_set
            foreach ($node->expectedPolicies() as $p_oid) {
                // that does not appear in a child node
                if (!$node->hasChildWithValidPolicy($p_oid)) {
                    $node->addChild(
                        new PolicyNode($p_oid, $policy->qualifiers(),
                            array($p_oid)));
                }
            }
        }
    }
    
    /**
     * Apply policy mappings to the policy tree.
     *
     * @param Certificate $cert
     * @param ValidatorState $state
     */
    protected function _applyMappings(Certificate $cert, ValidatorState $state)
    {
        $policy_mappings = $cert->tbsCertificate()
            ->extensions()
            ->policyMappings();
        // (6.1.4. b.1.) for each node in the valid_policy_tree of depth i...
        foreach ($policy_mappings->flattenedMappings() as $idp => $sdps) {
            $match_count = 0;
            foreach ($this->_nodesAtDepth($state->index()) as $node) {
                // ...where ID-P is the valid_policy
                if ($node->validPolicy() == $idp) {
                    // set expected_policy_set to the set of subjectDomainPolicy
                    // values that are specified as equivalent to ID-P by
                    // the policy mappings extension
                    $node->setExpectedPolicies(...$sdps);
                    ++$match_count;
                }
            }
            // if no node of depth i in the valid_policy_tree has
            // a valid_policy of ID-P...
            if (!$match_count) {
                $this->_applyAnyPolicyMapping($cert, $state, $idp, $sdps);
            }
        }
    }
    
    /**
     * Apply anyPolicy mapping to the policy tree as specified in 6.1.4 (b)(1).
     *
     * @param Certificate $cert
     * @param ValidatorState $state
     * @param string $idp OID of the issuer domain policy
     * @param array $sdps Array of subject domain policy OIDs
     */
    protected function _applyAnyPolicyMapping(Certificate $cert,
        ValidatorState $state, $idp, array $sdps)
    {
        // (6.1.4. b.1.) ...but there is a node of depth i with
        // a valid_policy of anyPolicy
        foreach ($this->_nodesAtDepth($state->index()) as $node) {
            if ($node->isAnyPolicy()) {
                // then generate a child node of the node of depth i-1
                // that has a valid_policy of anyPolicy as follows...
                foreach ($this->_nodesAtDepth($state->index() - 1) as $node) {
                    if ($node->isAnyPolicy()) {
                        // try to fetch qualifiers of anyPolicy certificate policy
                        $qualifiers = array();
                        try {
                            $qualifiers = $cert->tbsCertificate()
                                ->extensions()
                                ->certificatePolicies()
                                ->anyPolicy()
                                ->qualifiers();
                        } catch (\LogicException $e) {
                            // if there's no policies or no qualifiers
                        }
                        $node->addChild(
                            new PolicyNode($idp, $qualifiers, $sdps));
                        // bail after first anyPolicy has been processed
                        break;
                    }
                }
                // bail after first anyPolicy has been processed
                break;
            }
        }
    }
    
    /**
     * Delete nodes as specified in 6.1.4 (b)(2).
     *
     * @param Certificate $cert
     * @param ValidatorState $state
     */
    protected function _deleteMappings(Certificate $cert, ValidatorState $state)
    {
        $idps = $cert->tbsCertificate()
            ->extensions()
            ->policyMappings()
            ->issuerDomainPolicies();
        // delete each node of depth i in the valid_policy_tree
        // where ID-P is the valid_policy
        foreach ($this->_nodesAtDepth($state->index()) as $node) {
            if (in_array($node->validPolicy(), $idps)) {
                $node->remove();
            }
        }
        $this->_pruneTree($state->index() - 1);
    }
    
    /**
     * Prune tree starting from given depth.
     *
     * @param int $depth
     * @return int The number of nodes left in a tree
     */
    protected function _pruneTree(int $depth): int
    {
        for ($i = $depth; $i > 0; --$i) {
            foreach ($this->_nodesAtDepth($i) as $node) {
                if (!count($node)) {
                    $node->remove();
                }
            }
        }
        // if root has no children left
        if (!count($this->_root)) {
            $this->_root = null;
            return 0;
        }
        return $this->_root->nodeCount();
    }
    
    /**
     * Get all nodes at given depth.
     *
     * @param int $i
     * @return PolicyNode[]
     */
    protected function _nodesAtDepth(int $i): array
    {
        if (!$this->_root) {
            return array();
        }
        $depth = 0;
        $nodes = array($this->_root);
        while ($depth < $i) {
            $nodes = self::_gatherChildren(...$nodes);
            if (!count($nodes)) {
                break;
            }
            ++$depth;
        }
        return $nodes;
    }
    
    /**
     * Get the valid policy node set as specified in spec 6.1.5.(g)(iii)1.
     *
     * @return PolicyNode[]
     */
    protected function _validPolicyNodeSet(): array
    {
        // 1. Determine the set of policy nodes whose parent nodes have
        // a valid_policy of anyPolicy. This is the valid_policy_node_set.
        $set = array();
        if (!$this->_root) {
            return $set;
        }
        // for each node in a tree
        $this->_root->walkNodes(
            function (PolicyNode $node) use (&$set) {
                $parents = $node->parents();
                // node has parents
                if (count($parents)) {
                    // check that each ancestor is an anyPolicy node
                    foreach ($parents as $ancestor) {
                        if (!$ancestor->isAnyPolicy()) {
                            return;
                        }
                    }
                    $set[] = $node;
                }
            });
        return $set;
    }
    
    /**
     * Gather all children of given nodes to a flattened array.
     *
     * @param PolicyNode ...$nodes
     * @return PolicyNode[]
     */
    private static function _gatherChildren(PolicyNode ...$nodes): array
    {
        $children = array();
        foreach ($nodes as $node) {
            $children = array_merge($children, $node->children());
        }
        return $children;
    }
}
