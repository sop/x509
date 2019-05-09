<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements 'Issuer Alternative Name' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.7
 */
class IssuerAlternativeNameExtension extends Extension
{
    /**
     * Names.
     *
     * @var GeneralNames
     */
    protected $_names;

    /**
     * Constructor.
     *
     * @param bool         $critical
     * @param GeneralNames $names
     */
    public function __construct(bool $critical, GeneralNames $names)
    {
        parent::__construct(self::OID_ISSUER_ALT_NAME, $critical);
        $this->_names = $names;
    }

    /**
     * Get names.
     *
     * @return GeneralNames
     */
    public function names(): GeneralNames
    {
        return $this->_names;
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        return new self($critical,
            GeneralNames::fromASN1(
                UnspecifiedType::fromDER($data)->asSequence()));
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        return $this->_names->toASN1();
    }
}
