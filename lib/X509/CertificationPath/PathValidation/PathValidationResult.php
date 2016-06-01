<?php

namespace X509\CertificationPath\PathValidation;

use ASN1\Element;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use CryptoUtil\ASN1\PublicKeyInfo;
use X509\Certificate\Certificate;


/**
 * Result of the path validation process.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.6
 */
class PathValidationResult
{
	/**
	 * End-entity certificate.
	 *
	 * @var Certificate $_certificate
	 */
	protected $_certificate;
	
	/**
	 * Valid policy tree.
	 *
	 * @var mixed $_policyTree
	 */
	protected $_policyTree;
	
	/**
	 * End-entity certificate's public key.
	 *
	 * @var PublicKeyInfo
	 */
	protected $_publicKeyInfo;
	
	/**
	 * Public key algorithm.
	 *
	 * @var AlgorithmIdentifierType
	 */
	protected $_publicKeyAlgo;
	
	/**
	 * Public key parameters.
	 *
	 * @var Element|null $_publicKeyParameters
	 */
	protected $_publicKeyParameters;
	
	/**
	 * Constructor
	 *
	 * @param Certificate $cert
	 * @param mixed $policy_tree
	 * @param PublicKeyInfo $pubkey_info
	 * @param AlgorithmIdentifierType $algo
	 * @param Element|null $params
	 */
	public function __construct(Certificate $cert, $policy_tree, 
			PublicKeyInfo $pubkey_info, AlgorithmIdentifierType $algo, 
			Element $params = null) {
		$this->_certificate = $cert;
		$this->_policyTree = $policy_tree;
		$this->_publicKeyInfo = $pubkey_info;
		$this->_publicKeyAlgo = $algo;
		$this->_publicKeyParameters = $params;
	}
	
	/**
	 * Get end-entity certificate.
	 *
	 * @return Certificate
	 */
	public function certificate() {
		return $this->_certificate;
	}
}
