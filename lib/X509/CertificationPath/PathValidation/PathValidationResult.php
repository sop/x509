<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationPath\PathValidation;

use Sop\ASN1\Element;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\CertificationPath\Policy\PolicyTree;

/**
 * Result of the path validation process.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.6
 */
class PathValidationResult
{
    /**
     * Certificates in a certification path.
     *
     * @var Certificate[]
     */
    protected $_certificates;

    /**
     * Valid policy tree.
     *
     * @var null|PolicyTree
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
     * @var null|Element
     */
    protected $_publicKeyParameters;

    /**
     * Constructor.
     *
     * @param Certificate[]           $certificates Certificates in a certification path
     * @param null|PolicyTree         $policy_tree  Valid policy tree
     * @param PublicKeyInfo           $pubkey_info  Public key of the end-entity certificate
     * @param AlgorithmIdentifierType $algo         Public key algorithm of the end-entity certificate
     * @param null|Element            $params       Algorithm parameters
     */
    public function __construct(array $certificates, ?PolicyTree $policy_tree,
        PublicKeyInfo $pubkey_info, AlgorithmIdentifierType $algo,
        ?Element $params = null)
    {
        $this->_certificates = array_values($certificates);
        $this->_policyTree = $policy_tree;
        $this->_publicKeyInfo = $pubkey_info;
        $this->_publicKeyAlgo = $algo;
        $this->_publicKeyParameters = $params;
    }

    /**
     * Get end-entity certificate.
     */
    public function certificate(): Certificate
    {
        return $this->_certificates[count($this->_certificates) - 1];
    }

    /**
     * Get certificate policies of the end-entity certificate.
     *
     * @return PolicyInformation[]
     */
    public function policies(): array
    {
        if (!$this->_policyTree) {
            return [];
        }
        return $this->_policyTree->policiesAtDepth(count($this->_certificates));
    }
}
