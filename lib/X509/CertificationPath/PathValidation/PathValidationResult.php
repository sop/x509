<?php

declare(strict_types = 1);

namespace X509\CertificationPath\PathValidation;

use ASN1\Element;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use X509\Certificate\Certificate;

/**
 * Result of the path validation process.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.6
 */
class PathValidationResult
{
    /**
     * Certificates in a certification path.
     *
     * @var \X509\Certificate\Certificate[] $_certificates
     */
    protected $_certificates;
    
    /**
     * Valid policy tree.
     *
     * @var \X509\CertificationPath\Policy\PolicyTree|null $_policyTree
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
     * Constructor.
     *
     * @param \X509\Certificate\Certificate[] $certificates Certificates in a
     *        certification path
     * @param \X509\CertificationPath\Policy\PolicyTree|null $policy_tree Valid
     *        policy tree
     * @param PublicKeyInfo $pubkey_info Public key of the end-entity
     *        certificate
     * @param AlgorithmIdentifierType $algo Public key algorithm of the
     *        end-entity certificate
     * @param Element|null $params Algorithm parameters
     */
    public function __construct(array $certificates, $policy_tree,
        PublicKeyInfo $pubkey_info, AlgorithmIdentifierType $algo,
        Element $params = null)
    {
        $this->_certificates = array_values($certificates);
        $this->_policyTree = $policy_tree;
        $this->_publicKeyInfo = $pubkey_info;
        $this->_publicKeyAlgo = $algo;
        $this->_publicKeyParameters = $params;
    }
    
    /**
     * Get end-entity certificate.
     *
     * @return \X509\Certificate\Certificate
     */
    public function certificate(): Certificate
    {
        return $this->_certificates[count($this->_certificates) - 1];
    }
    
    /**
     * Get certificate policies of the end-entity certificate.
     *
     * @return \X509\Certificate\Extension\CertificatePolicy\PolicyInformation[]
     */
    public function policies(): array
    {
        if (!$this->_policyTree) {
            return array();
        }
        return $this->_policyTree->policiesAtDepth(count($this->_certificates));
    }
}
