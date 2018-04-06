<?php

declare(strict_types=1);

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\Certificate\Extension\DistributionPoint\DistributionPointName;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 */
class DistributionPointNameTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDecodeUnsupportedTypeFail()
    {
        $el = new ImplicitlyTaggedType(2, new NullType());
        DistributionPointName::fromTaggedType($el);
    }
}
