<?php

declare(strict_types = 1);

namespace X509\CertificationPath\PathValidation;

use Sop\CryptoBridge\Crypto;
use X509\Certificate\Certificate;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\CertificationPath\Exception\PathValidationException;

/**
 * Implements certification path validation.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6
 */
class PathValidator
{
    /**
     * Crypto engine.
     *
     * @var Crypto $_crypto
     */
    protected $_crypto;
    
    /**
     * Path validation configuration.
     *
     * @var PathValidationConfig $_config
     */
    protected $_config;
    
    /**
     * Certification path.
     *
     * @var Certificate[] $_certificates
     */
    protected $_certificates;
    
    /**
     * Certification path trust anchor.
     *
     * @var Certificate $_trustAnchor
     */
    protected $_trustAnchor;
    
    /**
     * Constructor.
     *
     * @param Crypto $crypto Crypto engine
     * @param PathValidationConfig $config Validation config
     * @param Certificate ...$certificates Certificates from the trust anchor to
     *        the end-entity certificate
     */
    public function __construct(Crypto $crypto, PathValidationConfig $config,
        Certificate ...$certificates)
    {
        if (!count($certificates)) {
            throw new \LogicException("No certificates.");
        }
        $this->_crypto = $crypto;
        $this->_config = $config;
        $this->_certificates = $certificates;
        // if trust anchor is explicitly given in configuration
        if ($config->hasTrustAnchor()) {
            $this->_trustAnchor = $config->trustAnchor();
        } else {
            $this->_trustAnchor = $certificates[0];
        }
    }
    
    /**
     * Validate certification path.
     *
     * @throws PathValidationException
     * @return PathValidationResult
     */
    public function validate(): PathValidationResult
    {
        $n = count($this->_certificates);
        $state = ValidatorState::initialize($this->_config, $this->_trustAnchor,
            $n);
        for ($i = 0; $i < $n; ++$i) {
            $state = $state->withIndex($i + 1);
            $cert = $this->_certificates[$i];
            // process certificate (section 6.1.3.)
            $state = $this->_processCertificate($state, $cert);
            if (!$state->isFinal()) {
                // prepare next certificate (section 6.1.4.)
                $state = $this->_prepareNext($state, $cert);
            }
        }
        if (!isset($cert)) {
            throw new \LogicException("No certificates.");
        }
        // wrap-up (section 6.1.5.)
        $state = $this->_wrapUp($state, $cert);
        // return outputs
        return $state->getResult($this->_certificates);
    }
    
    /**
     * Apply basic certificate processing according to RFC 5280 section 6.1.3.
     *
     * @link https://tools.ietf.org/html/rfc5280#section-6.1.3
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     * @return ValidatorState
     */
    private function _processCertificate(ValidatorState $state, Certificate $cert): ValidatorState
    {
        // (a.1) verify signature
        $this->_verifySignature($state, $cert);
        // (a.2) check validity period
        $this->_checkValidity($cert);
        // (a.3) check that certificate is not revoked
        $this->_checkRevocation($cert);
        // (a.4) check issuer
        $this->_checkIssuer($state, $cert);
        // (b)(c) if certificate is self-issued and it is not
        // the final certificate in the path, skip this step
        if (!($cert->isSelfIssued() && !$state->isFinal())) {
            // (b) check permitted subtrees
            $this->_checkPermittedSubtrees($state, $cert);
            // (c) check excluded subtrees
            $this->_checkExcludedSubtrees($state, $cert);
        }
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasCertificatePolicies()) {
            // (d) process policy information
            if ($state->hasValidPolicyTree()) {
                $state = $state->validPolicyTree()->processPolicies($state,
                    $cert);
            }
        } else {
            // (e) certificate policies extension not present,
            // set the valid_policy_tree to NULL
            $state = $state->withoutValidPolicyTree();
        }
        // (f) check that explicit_policy > 0 or valid_policy_tree is set
        if (!($state->explicitPolicy() > 0 || $state->hasValidPolicyTree())) {
            throw new PathValidationException("No valid policies.");
        }
        return $state;
    }
    
    /**
     * Apply preparation for the certificate i+1 according to rfc5280 section
     * 6.1.4.
     *
     * @link https://tools.ietf.org/html/rfc5280#section-6.1.4
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _prepareNext(ValidatorState $state, Certificate $cert): ValidatorState
    {
        // (a)(b) if policy mappings extension is present
        $state = $this->_preparePolicyMappings($state, $cert);
        // (c) assign working_issuer_name
        $state = $state->withWorkingIssuerName(
            $cert->tbsCertificate()
                ->subject());
        // (d)(e)(f)
        $state = $this->_setPublicKeyState($state, $cert);
        // (g) if name constraints extension is present
        $state = $this->_prepareNameConstraints($state, $cert);
        // (h) if certificate is not self-issued
        if (!$cert->isSelfIssued()) {
            $state = $this->_prepareNonSelfIssued($state);
        }
        // (i) if policy constraints extension is present
        $state = $this->_preparePolicyConstraints($state, $cert);
        // (j) if inhibit any policy extension is present
        $state = $this->_prepareInhibitAnyPolicy($state, $cert);
        // (k) check basic constraints
        $this->_processBasicContraints($cert);
        // (l) verify max_path_length
        $state = $this->_verifyMaxPathLength($state, $cert);
        // (m) check pathLenContraint
        $state = $this->_processPathLengthContraint($state, $cert);
        // (n) check key usage
        $this->_checkKeyUsage($cert);
        // (o) process relevant extensions
        $state = $this->_processExtensions($state, $cert);
        return $state;
    }
    
    /**
     * Apply wrap-up procedure according to RFC 5280 section 6.1.5.
     *
     * @link https://tools.ietf.org/html/rfc5280#section-6.1.5
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     * @return ValidatorState
     */
    private function _wrapUp(ValidatorState $state, Certificate $cert): ValidatorState
    {
        $tbs_cert = $cert->tbsCertificate();
        $extensions = $tbs_cert->extensions();
        // (a)
        if ($state->explicitPolicy() > 0) {
            $state = $state->withExplicitPolicy($state->explicitPolicy() - 1);
        }
        // (b)
        if ($extensions->hasPolicyConstraints()) {
            $ext = $extensions->policyConstraints();
            if ($ext->hasRequireExplicitPolicy() &&
                 $ext->requireExplicitPolicy() == 0) {
                $state = $state->withExplicitPolicy(0);
            }
        }
        // (c)(d)(e)
        $state = $this->_setPublicKeyState($state, $cert);
        // (f) process relevant extensions
        $state = $this->_processExtensions($state, $cert);
        // (g) intersection of valid_policy_tree and the initial-policy-set
        $state = $this->_calculatePolicyIntersection($state);
        // check that explicit_policy > 0 or valid_policy_tree is set
        if (!($state->explicitPolicy() > 0 || $state->hasValidPolicyTree())) {
            throw new PathValidationException("No valid policies.");
        }
        // path validation succeeded
        return $state;
    }
    
    /**
     * Update working_public_key, working_public_key_parameters and
     * working_public_key_algorithm state variables from certificate.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _setPublicKeyState(ValidatorState $state, Certificate $cert): ValidatorState
    {
        $pk_info = $cert->tbsCertificate()->subjectPublicKeyInfo();
        // assign working_public_key
        $state = $state->withWorkingPublicKey($pk_info);
        // assign working_public_key_parameters
        $params = ValidatorState::getAlgorithmParameters(
            $pk_info->algorithmIdentifier());
        if (null !== $params) {
            $state = $state->withWorkingPublicKeyParameters($params);
        } else {
            // if algorithms differ, set parameters to null
            if ($pk_info->algorithmIdentifier()->oid() !==
                 $state->workingPublicKeyAlgorithm()->oid()) {
                $state = $state->withWorkingPublicKeyParameters(null);
            }
        }
        // assign working_public_key_algorithm
        $state = $state->withWorkingPublicKeyAlgorithm(
            $pk_info->algorithmIdentifier());
        return $state;
    }
    
    /**
     * Verify certificate signature.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     */
    private function _verifySignature(ValidatorState $state, Certificate $cert)
    {
        try {
            $valid = $cert->verify($state->workingPublicKey(), $this->_crypto);
        } catch (\RuntimeException $e) {
            throw new PathValidationException(
                "Failed to verify signature: " . $e->getMessage(), 0, $e);
        }
        if (!$valid) {
            throw new PathValidationException(
                "Certificate signature doesn't match.");
        }
    }
    
    /**
     * Check certificate validity.
     *
     * @param Certificate $cert
     * @throws PathValidationException
     */
    private function _checkValidity(Certificate $cert)
    {
        $refdt = $this->_config->dateTime();
        $validity = $cert->tbsCertificate()->validity();
        if ($validity->notBefore()
            ->dateTime()
            ->diff($refdt)->invert) {
            throw new PathValidationException(
                "Certificate validity period has not started.");
        }
        if ($refdt->diff($validity->notAfter()
            ->dateTime())->invert) {
            throw new PathValidationException("Certificate has expired.");
        }
    }
    
    /**
     * Check certificate revocation.
     *
     * @param Certificate $cert
     */
    private function _checkRevocation(Certificate $cert)
    {
        // @todo Implement CRL handling
    }
    
    /**
     * Check certificate issuer.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     */
    private function _checkIssuer(ValidatorState $state, Certificate $cert)
    {
        if (!$cert->tbsCertificate()
            ->issuer()
            ->equals($state->workingIssuerName())) {
            throw new PathValidationException("Certification issuer mismatch.");
        }
    }
    
    /**
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     */
    private function _checkPermittedSubtrees(ValidatorState $state,
        Certificate $cert)
    {
        // @todo Implement
        $state->permittedSubtrees();
    }
    
    /**
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     */
    private function _checkExcludedSubtrees(ValidatorState $state,
        Certificate $cert)
    {
        // @todo Implement
        $state->excludedSubtrees();
    }
    
    /**
     * Apply policy mappings handling for the preparation step.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     * @return ValidatorState
     */
    private function _preparePolicyMappings(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasPolicyMappings()) {
            // (a) verify that anyPolicy mapping is not used
            if ($extensions->policyMappings()->hasAnyPolicyMapping()) {
                throw new PathValidationException("anyPolicy mapping found.");
            }
            // (b) process policy mappings
            if ($state->hasValidPolicyTree()) {
                $state = $state->validPolicyTree()->processMappings($state,
                    $cert);
            }
        }
        return $state;
    }
    
    /**
     * Apply name constraints handling for the preparation step.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _prepareNameConstraints(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasNameConstraints()) {
            $state = $this->_processNameConstraints($state, $cert);
        }
        return $state;
    }
    
    /**
     * Apply preparation for a non-self-signed certificate.
     *
     * @param ValidatorState $state
     * @return ValidatorState
     */
    private function _prepareNonSelfIssued(ValidatorState $state): ValidatorState
    {
        // (h.1)
        if ($state->explicitPolicy() > 0) {
            $state = $state->withExplicitPolicy($state->explicitPolicy() - 1);
        }
        // (h.2)
        if ($state->policyMapping() > 0) {
            $state = $state->withPolicyMapping($state->policyMapping() - 1);
        }
        // (h.3)
        if ($state->inhibitAnyPolicy() > 0) {
            $state = $state->withInhibitAnyPolicy(
                $state->inhibitAnyPolicy() - 1);
        }
        return $state;
    }
    
    /**
     * Apply policy constraints handling for the preparation step.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _preparePolicyConstraints(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if (!$extensions->hasPolicyConstraints()) {
            return $state;
        }
        $ext = $extensions->policyConstraints();
        // (i.1)
        if ($ext->hasRequireExplicitPolicy() &&
             $ext->requireExplicitPolicy() < $state->explicitPolicy()) {
            $state = $state->withExplicitPolicy($ext->requireExplicitPolicy());
        }
        // (i.2)
        if ($ext->hasInhibitPolicyMapping() &&
             $ext->inhibitPolicyMapping() < $state->policyMapping()) {
            $state = $state->withPolicyMapping($ext->inhibitPolicyMapping());
        }
        return $state;
    }
    
    /**
     * Apply inhibit any-policy handling for the preparation step.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _prepareInhibitAnyPolicy(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasInhibitAnyPolicy()) {
            $ext = $extensions->inhibitAnyPolicy();
            if ($ext->skipCerts() < $state->inhibitAnyPolicy()) {
                $state = $state->withInhibitAnyPolicy($ext->skipCerts());
            }
        }
        return $state;
    }
    
    /**
     * Verify maximum certification path length for the preparation step.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @throws PathValidationException
     * @return ValidatorState
     */
    private function _verifyMaxPathLength(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        if (!$cert->isSelfIssued()) {
            if ($state->maxPathLength() <= 0) {
                throw new PathValidationException(
                    "Certification path length exceeded.");
            }
            $state = $state->withMaxPathLength($state->maxPathLength() - 1);
        }
        return $state;
    }
    
    /**
     * Check key usage extension for the preparation step.
     *
     * @param Certificate $cert
     * @throws PathValidationException
     */
    private function _checkKeyUsage(Certificate $cert)
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasKeyUsage()) {
            $ext = $extensions->keyUsage();
            if (!$ext->isKeyCertSign()) {
                throw new PathValidationException("keyCertSign usage not set.");
            }
        }
    }
    
    /**
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _processNameConstraints(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        // @todo Implement
        return $state;
    }
    
    /**
     * Process basic constraints extension.
     *
     * @param Certificate $cert
     * @throws PathValidationException
     */
    private function _processBasicContraints(Certificate $cert)
    {
        if ($cert->tbsCertificate()->version() == TBSCertificate::VERSION_3) {
            $extensions = $cert->tbsCertificate()->extensions();
            if (!$extensions->hasBasicConstraints()) {
                throw new PathValidationException(
                    "v3 certificate must have basicConstraints extension.");
            }
            // verify that cA is set to TRUE
            if (!$extensions->basicConstraints()->isCA()) {
                throw new PathValidationException(
                    "Certificate is not a CA certificate.");
            }
        }
    }
    
    /**
     * Process pathLenConstraint.
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _processPathLengthContraint(ValidatorState $state,
        Certificate $cert): ValidatorState
    {
        $extensions = $cert->tbsCertificate()->extensions();
        if ($extensions->hasBasicConstraints()) {
            $ext = $extensions->basicConstraints();
            if ($ext->hasPathLen()) {
                if ($ext->pathLen() < $state->maxPathLength()) {
                    $state = $state->withMaxPathLength($ext->pathLen());
                }
            }
        }
        return $state;
    }
    
    /**
     *
     * @param ValidatorState $state
     * @param Certificate $cert
     * @return ValidatorState
     */
    private function _processExtensions(ValidatorState $state, Certificate $cert): ValidatorState
    {
        // @todo Implement
        return $state;
    }
    
    /**
     *
     * @param ValidatorState $state
     * @return ValidatorState
     */
    private function _calculatePolicyIntersection(ValidatorState $state): ValidatorState
    {
        // (i) If the valid_policy_tree is NULL, the intersection is NULL
        if (!$state->hasValidPolicyTree()) {
            return $state;
        }
        // (ii) If the valid_policy_tree is not NULL and
        // the user-initial-policy-set is any-policy, the intersection
        // is the entire valid_policy_tree
        $initial_policies = $this->_config->policySet();
        if (in_array(PolicyInformation::OID_ANY_POLICY, $initial_policies)) {
            return $state;
        }
        // (iii) If the valid_policy_tree is not NULL and the
        // user-initial-policy-set is not any-policy, calculate
        // the intersection of the valid_policy_tree and the
        // user-initial-policy-set as follows
        return $state->validPolicyTree()->calculateIntersection($state,
            $initial_policies);
    }
}
