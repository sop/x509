<?php

namespace X509\CertificationPath\PathValidation;

use X509\Certificate\Certificate;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;

/**
 * Configuration for the certification path validation process.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.1
 */
class PathValidationConfig
{
    /**
     * Maximum allowed certification path length.
     *
     * @var int $_maxLength
     */
    protected $_maxLength;
    
    /**
     * Reference time.
     *
     * @var \DateTimeImmutable $_dateTime
     */
    protected $_dateTime;
    
    /**
     * List of acceptable policy identifiers.
     *
     * @var string[] $_policySet
     */
    protected $_policySet;
    
    /**
     * Trust anchor certificate.
     *
     * If not set, path validation uses the first certificate of the path.
     *
     * @var Certificate|null $_trustAnchor
     */
    protected $_trustAnchor;
    
    /**
     * Whether policy mapping in inhibited.
     *
     * Setting this to true disallows policy mapping.
     *
     * @var bool $_policyMappingInhibit
     */
    protected $_policyMappingInhibit;
    
    /**
     * Whether the path must be valid for at least one policy in the
     * initial policy set.
     *
     * @var bool $_explicitPolicy
     */
    protected $_explicitPolicy;
    
    /**
     * Whether anyPolicy OID processing should be inhibited.
     *
     * Setting this to true disallows the usage of anyPolicy.
     *
     * @var bool $_anyPolicyInhibit
     */
    protected $_anyPolicyInhibit;
    
    /**
     *
     * @todo Implement
     * @var unknown $_permittedSubtrees
     */
    protected $_permittedSubtrees;
    
    /**
     *
     * @todo Implement
     * @var unknown $_excludedSubtrees
     */
    protected $_excludedSubtrees;
    
    /**
     * Constructor.
     *
     * @param \DateTimeImmutable $dt Reference date and time
     * @param int $max_length Maximum certification path length
     */
    public function __construct(\DateTimeImmutable $dt, $max_length)
    {
        $this->_dateTime = $dt;
        $this->_maxLength = (int) $max_length;
        $this->_policySet = array((string) PolicyInformation::OID_ANY_POLICY);
        $this->_policyMappingInhibit = false;
        $this->_explicitPolicy = false;
        $this->_anyPolicyInhibit = false;
    }
    
    /**
     * Get default configuration.
     *
     * @return self
     */
    public static function defaultConfig()
    {
        return new self(new \DateTimeImmutable(), 3);
    }
    
    /**
     * Get self with maximum path length.
     *
     * @param int $length
     * @return self
     */
    public function withMaxLength($length)
    {
        $obj = clone $this;
        $obj->_maxLength = $length;
        return $obj;
    }
    
    /**
     * Get self with reference date and time.
     *
     * @param \DateTimeImmutable $dt
     * @return self
     */
    public function withDateTime(\DateTimeImmutable $dt)
    {
        $obj = clone $this;
        $obj->_dateTime = $dt;
        return $obj;
    }
    
    /**
     * Get self with trust anchor certificate.
     *
     * @param Certificate $ca
     * @return self
     */
    public function withTrustAnchor(Certificate $ca)
    {
        $obj = clone $this;
        $obj->_trustAnchor = $ca;
        return $obj;
    }
    
    /**
     * Get self with initial-policy-mapping-inhibit set.
     *
     * @param bool $flag
     * @return self
     */
    public function withPolicyMappingInhibit($flag)
    {
        $obj = clone $this;
        $obj->_policyMappingInhibit = (bool) $flag;
        return $obj;
    }
    
    /**
     * Get self with initial-explicit-policy set.
     *
     * @param bool $flag
     * @return self
     */
    public function withExplicitPolicy($flag)
    {
        $obj = clone $this;
        $obj->_explicitPolicy = (bool) $flag;
        return $obj;
    }
    
    /**
     * Get self with initial-any-policy-inhibit set.
     *
     * @param bool $flag
     * @return self
     */
    public function withAnyPolicyInhibit($flag)
    {
        $obj = clone $this;
        $obj->_anyPolicyInhibit = (bool) $flag;
        return $obj;
    }
    
    /**
     * Get self with user-initial-policy-set set to policy OIDs.
     *
     * @param string ...$policies List of policy OIDs
     * @return self
     */
    public function withPolicySet(...$policies)
    {
        $obj = clone $this;
        $obj->_policySet = $policies;
        return $obj;
    }
    
    /**
     * Get maximum certification path length.
     *
     * @return int
     */
    public function maxLength()
    {
        return $this->_maxLength;
    }
    
    /**
     * Get reference date and time.
     *
     * @return \DateTimeImmutable
     */
    public function dateTime()
    {
        return $this->_dateTime;
    }
    
    /**
     * Get user-initial-policy-set.
     *
     * @return string[] Array of OID's
     */
    public function policySet()
    {
        return $this->_policySet;
    }
    
    /**
     * Check whether trust anchor certificate is set.
     *
     * @return bool
     */
    public function hasTrustAnchor()
    {
        return isset($this->_trustAnchor);
    }
    
    /**
     * Get trust anchor certificate.
     *
     * @throws \LogicException
     * @return Certificate
     */
    public function trustAnchor()
    {
        if (!$this->hasTrustAnchor()) {
            throw new \LogicException("No trust anchor.");
        }
        return $this->_trustAnchor;
    }
    
    /**
     * Get initial-policy-mapping-inhibit.
     *
     * @return bool
     */
    public function policyMappingInhibit()
    {
        return $this->_policyMappingInhibit;
    }
    
    /**
     * Get initial-explicit-policy.
     *
     * @return bool
     */
    public function explicitPolicy()
    {
        return $this->_explicitPolicy;
    }
    
    /**
     * Get initial-any-policy-inhibit.
     *
     * @return bool
     */
    public function anyPolicyInhibit()
    {
        return $this->_anyPolicyInhibit;
    }
}
