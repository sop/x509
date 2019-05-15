<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\AccessDescription;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\X509\GeneralName\GeneralName;

/**
 * Base class implementing *AccessDescription* ASN.1 type for
 * 'Authority Information Access' and 'Subject Information Access' certificate
 * extensions.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.1
 */
abstract class AccessDescription
{
    /**
     * Access method OID.
     *
     * @var string
     */
    protected $_accessMethod;

    /**
     * Access location.
     *
     * @var GeneralName
     */
    protected $_accessLocation;

    /**
     * Constructor.
     *
     * @param string      $method   Access method OID
     * @param GeneralName $location Access location
     */
    public function __construct(string $method, GeneralName $location)
    {
        $this->_accessMethod = $method;
        $this->_accessLocation = $location;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        return new static($seq->at(0)->asObjectIdentifier()->oid(),
            GeneralName::fromASN1($seq->at(1)->asTagged()));
    }

    /**
     * Get the access method OID.
     *
     * @return string
     */
    public function accessMethod(): string
    {
        return $this->_accessMethod;
    }

    /**
     * Get the access location.
     *
     * @return GeneralName
     */
    public function accessLocation(): GeneralName
    {
        return $this->_accessLocation;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new ObjectIdentifier($this->_accessMethod),
            $this->_accessLocation->toASN1());
    }
}
