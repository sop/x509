<?php

declare(strict_types=1);

namespace X509\AttributeCertificate\Validation;

use X509\Certificate\Extension\Target\Target;
use X509\CertificationPath\CertificationPath;

/**
 * Provides configuration context for the attribute certificate validation.
 */
class ACValidationConfig
{
    /**
     * Certification path of the AC holder.
     *
     * @var CertificationPath
     */
    protected $_holderPath;
    
    /**
     * Certification path of the AC issuer.
     *
     * @var CertificationPath
     */
    protected $_issuerPath;
    
    /**
     * Evaluation reference time.
     *
     * @var \DateTimeImmutable
     */
    protected $_evalTime;
    
    /**
     * Permitted targets.
     *
     * @var Target[]
     */
    protected $_targets;
    
    /**
     * Constructor.
     *
     * @param CertificationPath $holder_path Certification path of the AC holder
     * @param CertificationPath $issuer_path Certification path of the AC issuer
     */
    public function __construct(CertificationPath $holder_path,
        CertificationPath $issuer_path)
    {
        $this->_holderPath = $holder_path;
        $this->_issuerPath = $issuer_path;
        $this->_evalTime = new \DateTimeImmutable();
        $this->_targets = array();
    }
    
    /**
     * Get certification path of the AC's holder.
     *
     * @return CertificationPath
     */
    public function holderPath()
    {
        return $this->_holderPath;
    }
    
    /**
     * Get certification path of the AC's issuer.
     *
     * @return CertificationPath
     */
    public function issuerPath()
    {
        return $this->_issuerPath;
    }
    
    /**
     * Get self with given evaluation reference time.
     *
     * @param \DateTimeImmutable $dt
     * @return self
     */
    public function withEvaluationTime(\DateTimeImmutable $dt)
    {
        $obj = clone $this;
        $obj->_evalTime = $dt;
        return $obj;
    }
    
    /**
     * Get the evaluation reference time.
     *
     * @return \DateTimeImmutable
     */
    public function evaluationTime()
    {
        return $this->_evalTime;
    }
    
    /**
     * Get self with permitted targets.
     *
     * @param Target ...$targets
     * @return self
     */
    public function withTargets(Target ...$targets)
    {
        $obj = clone $this;
        $obj->_targets = $targets;
        return $obj;
    }
    
    /**
     * Get array of permitted targets
     *
     * @return Target[]
     */
    public function targets()
    {
        return $this->_targets;
    }
}
