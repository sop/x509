<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Element;

/**
 * Class to park payload of an unknown extension.
 */
class UnknownExtension extends Extension
{
    /**
     * Extension value.
     *
     * @var Element $_element
     */
    protected $_element;
    
    /**
     * Constructor.
     *
     * @param string $oid
     * @param bool $critical
     * @param Element $data
     */
    public function __construct(string $oid, bool $critical, Element $data)
    {
        parent::__construct($oid, $critical);
        $this->_element = $data;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        return $this->_element;
    }
}
