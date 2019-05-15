<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Element;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * Implements 'fullName' ASN.1 CHOICE type of *DistributionPointName*
 * used by 'CRL Distribution Points' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class FullName extends DistributionPointName
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
     * @param GeneralNames $names
     */
    public function __construct(GeneralNames $names)
    {
        $this->_tag = self::TAG_FULL_NAME;
        $this->_names = $names;
    }

    /**
     * Initialize with a single URI.
     *
     * @param string $uri
     *
     * @return self
     */
    public static function fromURI(string $uri): self
    {
        return new self(new GeneralNames(new UniformResourceIdentifier($uri)));
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
    protected function _valueASN1(): Element
    {
        return $this->_names->toASN1();
    }
}
