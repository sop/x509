<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Type\Primitive\Integer;

/**
 * Implements 'Inhibit anyPolicy' extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.14
 */
class InhibitAnyPolicyExtension extends Extension
{
    /**
     *
     * @var int $_skipCerts
     */
    protected $_skipCerts;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param int $skip_certs
     */
    public function __construct(bool $critical, int $skip_certs)
    {
        parent::__construct(self::OID_INHIBIT_ANY_POLICY, $critical);
        $this->_skipCerts = $skip_certs;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical): self
    {
        return new self($critical, Integer::fromDER($data)->intNumber());
    }
    
    /**
     * Get value.
     *
     * @return int
     */
    public function skipCerts(): int
    {
        return $this->_skipCerts;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Integer
     */
    protected function _valueASN1(): Integer
    {
        return new Integer($this->_skipCerts);
    }
}
