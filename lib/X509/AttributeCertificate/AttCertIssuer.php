<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Base class implementing *AttCertIssuer* ASN.1 CHOICE type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
abstract class AttCertIssuer
{
    /**
     * Generate ASN.1 element.
     */
    abstract public function toASN1(): Element;

    /**
     * Check whether AttCertIssuer identifies given certificate.
     */
    abstract public function identifiesPKC(Certificate $cert): bool;

    /**
     * Initialize from distinguished name.
     *
     * This conforms to RFC 5755 which states that only v2Form must be used,
     * and issuerName must contain exactly one GeneralName of DirectoryName
     * type.
     *
     * @see https://tools.ietf.org/html/rfc5755#section-4.2.3
     */
    public static function fromName(Name $name): self
    {
        return new V2Form(new GeneralNames(new DirectoryName($name)));
    }

    /**
     * Initialize from an issuer's public key certificate.
     */
    public static function fromPKC(Certificate $cert): self
    {
        return self::fromName($cert->tbsCertificate()->subject());
    }

    /**
     * Initialize from ASN.1.
     *
     * @param UnspecifiedType $el CHOICE
     *
     * @throws \UnexpectedValueException
     */
    public static function fromASN1(UnspecifiedType $el): self
    {
        if (!$el->isTagged()) {
            throw new \UnexpectedValueException('v1Form issuer not supported.');
        }
        $tagged = $el->asTagged();
        switch ($tagged->tag()) {
            case 0:
                return V2Form::fromV2ASN1(
                    $tagged->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
        }
        throw new \UnexpectedValueException('Unsupported issuer type.');
    }
}
