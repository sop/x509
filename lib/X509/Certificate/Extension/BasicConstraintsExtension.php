<?php

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Boolean;
use ASN1\Type\Primitive\Integer;

/**
 * Implements 'Basic Constraints' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.9
 */
class BasicConstraintsExtension extends Extension
{
    /**
     * Whether certificate is a CA.
     *
     * @var boolean $_ca
     */
    protected $_ca;
    
    /**
     * Maximum certification path length.
     *
     * @var int|null $_pathLen
     */
    protected $_pathLen;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param bool $ca
     * @param int|null $path_len
     */
    public function __construct($critical, $ca, $path_len = null)
    {
        parent::__construct(self::OID_BASIC_CONSTRAINTS, $critical);
        $this->_ca = (bool) $ca;
        $this->_pathLen = $path_len;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER($data, $critical)
    {
        $seq = Sequence::fromDER($data);
        $ca = false;
        $path_len = null;
        $idx = 0;
        if ($seq->has($idx, Element::TYPE_BOOLEAN)) {
            $ca = $seq->at($idx++)
                ->asBoolean()
                ->value();
        }
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $path_len = $seq->at($idx)
                ->asInteger()
                ->number();
        }
        return new self($critical, $ca, $path_len);
    }
    
    /**
     * Whether certificate is a CA.
     *
     * @return bool
     */
    public function isCA()
    {
        return $this->_ca;
    }
    
    /**
     * Whether path length is present.
     *
     * @return bool
     */
    public function hasPathLen()
    {
        return isset($this->_pathLen);
    }
    
    /**
     * Get path length.
     *
     * @throws \LogicException
     * @return int
     */
    public function pathLen()
    {
        if (!$this->hasPathLen()) {
            throw new \LogicException("pathLenConstraint not set.");
        }
        return $this->_pathLen;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Sequence
     */
    protected function _valueASN1()
    {
        $elements = array();
        if ($this->_ca) {
            $elements[] = new Boolean(true);
        }
        if (isset($this->_pathLen)) {
            $elements[] = new Integer($this->_pathLen);
        }
        return new Sequence(...$elements);
    }
}
