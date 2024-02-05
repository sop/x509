<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 *
 * @internal
 */
class DistributionPointNameTest extends TestCase
{
    public function testDecodeUnsupportedTypeFail()
    {
        $el = new ImplicitlyTaggedType(2, new NullType());
        $this->expectException(UnexpectedValueException::class);
        DistributionPointName::fromTaggedType($el);
    }
}
