<?php

namespace X509\AttributeCertificate\Validation;

use Sop\CryptoBridge\Crypto;
use X509\AttributeCertificate\AttributeCertificate;
use X509\AttributeCertificate\Validation\Exception\ACValidationException;
use X509\Certificate\Certificate;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\TargetInformationExtension;
use X509\Certificate\Extension\Target\Targets;
use X509\CertificationPath\Exception\PathValidationException;
use X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Implements attribute certificate validation conforming to RFC 5755.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-5
 */
class ACValidator
{
    /**
     * Attribute certificate.
     *
     * @var AttributeCertificate
     */
    protected $_ac;
    
    /**
     * Validation configuration.
     *
     * @var ACValidationConfig
     */
    protected $_config;
    
    /**
     * Crypto engine.
     *
     * @var Crypto
     */
    protected $_crypto;
    
    /**
     * Constructor.
     *
     * @param AttributeCertificate $ac Attribute certificate to validate
     * @param ACValidationConfig $config Validation configuration
     * @param Crypto $crypto Crypto engine
     */
    public function __construct(AttributeCertificate $ac,
        ACValidationConfig $config, Crypto $crypto)
    {
        $this->_ac = $ac;
        $this->_config = $config;
        $this->_crypto = $crypto;
    }
    
    /**
     * Validate attribute certificate.
     *
     * @throws ACValidationException If validation fails
     * @return AttributeCertificate Validated AC
     */
    public function validate()
    {
        $this->_validateHolder();
        $issuer = $this->_verifyIssuer();
        $this->_validateIssuerProfile($issuer);
        $this->_validateTime();
        $this->_validateTargeting();
        return $this->_ac;
    }
    
    /**
     * Validate AC holder's certification.
     *
     * @throws ACValidationException
     * @return Certificate Certificate of the AC's holder
     */
    private function _validateHolder()
    {
        $path = $this->_config->holderPath();
        $config = PathValidationConfig::defaultConfig()->withMaxLength(
            count($path))->withDateTime($this->_config->evaluationTime());
        try {
            $holder = $path->validate($this->_crypto, $config)->certificate();
        } catch (PathValidationException $e) {
            throw new ACValidationException(
                "Failed to validate holder PKC's certification path.", null, $e);
        }
        if (!$this->_ac->isHeldBy($holder)) {
            throw new ACValidationException("Name mismatch of AC's holder PKC.");
        }
        return $holder;
    }
    
    /**
     * Verify AC's signature and issuer's certification.
     *
     * @throws ACValidationException
     * @return Certificate Certificate of the AC's issuer
     */
    private function _verifyIssuer()
    {
        $path = $this->_config->issuerPath();
        $config = PathValidationConfig::defaultConfig()->withMaxLength(
            count($path))->withDateTime($this->_config->evaluationTime());
        try {
            $issuer = $path->validate($this->_crypto, $config)->certificate();
        } catch (PathValidationException $e) {
            throw new ACValidationException(
                "Failed to validate issuer PKC's certification path.", null, $e);
        }
        if (!$this->_ac->isIssuedBy($issuer)) {
            throw new ACValidationException("Name mismatch of AC's issuer PKC.");
        }
        $pubkey_info = $issuer->tbsCertificate()->subjectPublicKeyInfo();
        if (!$this->_ac->verify($this->_crypto, $pubkey_info)) {
            throw new ACValidationException("Failed to verify signature.");
        }
        return $issuer;
    }
    
    /**
     * Validate AC issuer's profile.
     *
     * @link https://tools.ietf.org/html/rfc5755#section-4.5
     * @param Certificate $cert
     * @throws ACValidationException
     */
    private function _validateIssuerProfile(Certificate $cert)
    {
        $exts = $cert->tbsCertificate()->extensions();
        if ($exts->hasKeyUsage() && !$exts->keyUsage()->isDigitalSignature()) {
            throw new ACValidationException(
                "Issuer PKC's Key Usage extension doesn't permit" .
                     " verification of digital signatures.");
        }
        if ($exts->hasBasicConstraints() && $exts->basicConstraints()->isCA()) {
            throw new ACValidationException("Issuer PKC must not be a CA.");
        }
    }
    
    /**
     * Validate AC's validity period.
     *
     * @throws ACValidationException
     */
    private function _validateTime()
    {
        $t = $this->_config->evaluationTime();
        $validity = $this->_ac->acinfo()->validityPeriod();
        if ($validity->notBeforeTime()->diff($t)->invert) {
            throw new ACValidationException("Validity period has not started.");
        }
        if ($t->diff($validity->notAfterTime())->invert) {
            throw new ACValidationException("Attribute certificate has expired.");
        }
    }
    
    /**
     * Validate AC's target information.
     *
     * @throws ACValidationException
     */
    private function _validateTargeting()
    {
        $exts = $this->_ac->acinfo()->extensions();
        // if target information extension is not present
        if (!$exts->has(Extension::OID_TARGET_INFORMATION)) {
            return;
        }
        $ext = $exts->get(Extension::OID_TARGET_INFORMATION);
        if ($ext instanceof TargetInformationExtension &&
             !$this->_hasMatchingTarget($ext->targets())) {
            throw new ACValidationException(
                "Attribute certificate doesn't have a matching target.");
        }
    }
    
    /**
     * Check whether validation configuration has matching targets.
     *
     * @param Targets $targets Set of eligible targets
     * @return boolean
     */
    private function _hasMatchingTarget(Targets $targets)
    {
        foreach ($this->_config->targets() as $target) {
            if ($targets->hasTarget($target)) {
                return true;
            }
        }
        return false;
    }
}
