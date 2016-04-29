<?php

namespace X509\CertificationPath\Policy;

use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;


class PolicyNode
{
	protected $_validPolicy;
	
	protected $_qualifiers;
	
	protected $_expectedPolicies;
	
	public function __constructor($valid_policy, array $qualifiers, 
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
