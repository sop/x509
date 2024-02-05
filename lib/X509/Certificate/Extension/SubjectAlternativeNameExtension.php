<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements 'Subject Alternative Name' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class SubjectAlternativeNameExtension extends Extension
{
    /**
     * Names.
     *
     * @var GeneralNames
     */
    protected $_names;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, GeneralNames $names)
    {
        parent::__construct(self::OID_SUBJECT_ALT_NAME, $critical);
        $this->_names = $names;
    }

    /**
     * Get names.
     */
    public function names(): GeneralNames
    {
        return $this->_names;
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        return new self($critical,
            GeneralNames::fromASN1(
                UnspecifiedType::fromDER($data)->asSequence()));
    }

    protected function _valueASN1(): Element
    {
        return $this->_names->toASN1();
    }
}
