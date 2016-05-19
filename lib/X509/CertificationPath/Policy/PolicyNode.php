<?php

namespace X509\CertificationPath\Policy;

use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;


/**
 * Policy node class for certification path validation.
 *
 * @todo Implement
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.2
 */
class PolicyNode
{
	protected $_validPolicy;
	
	protected $_qualifiers;
	
	protected $_expectedPolicies;
	
	/**
	 * Constructor
	 *
	 * @param string $valid_policy Policy OID
	 * @param array $qualifiers
	 * @param array $expected_policies
	 */
	public function __construct($valid_policy, array $qualifiers, 
			array $expected_policies) {
		$this->_validPolicy = $valid_policy;
		$this->_qualifiers = $qualifiers;
		$this->_expectedPolicies = $expected_policies;
	}
	
	public static function anyPolicyNode() {
		return new self(PolicyInformation::OID_ANY_POLICY, array(), 
			array(PolicyInformation::OID_ANY_POLICY));
	}
}
