<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\OctetString;

/**
 * Class to park payload of an unknown extension.
 */
class UnknownExtension extends Extension
{
    /**
     * Decoded extension value.
     *
     * @var null|Element
     */
    protected $_element;

    /**
     * Raw extension value.
     *
     * @var string
     */
    protected $_data;

    /**
     * Constructor.
     */
    public function __construct(string $oid, bool $critical, Element $element)
    {
        parent::__construct($oid, $critical);
        $this->_element = $element;
        $this->_data = $element->toDER();
    }

    /**
     * Create instance from a raw encoded extension value.
     */
    public static function fromRawString(string $oid, bool $critical,
        string $data): self
    {
        $obj = new self($oid, $critical, new OctetString(''));
        $obj->_element = null;
        $obj->_data = $data;
        return $obj;
    }

    /**
     * Get the encoded extension value.
     */
    public function extensionValue(): string
    {
        return $this->_data;
    }

    protected function _extnValue(): OctetString
    {
        return new OctetString($this->_data);
    }

    protected function _valueASN1(): Element
    {
        if (!isset($this->_element)) {
            throw new \RuntimeException('Extension value is not DER encoded.');
        }
        return $this->_element;
    }
}
