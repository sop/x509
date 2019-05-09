<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\IPAddress;

/**
 * @group general-name
 *
 * @internal
 */
class IPAddressNameTest extends TestCase
{
    public function testInvalidASN1()
    {
        $el = new ImplicitlyTaggedType(GeneralName::TAG_IP_ADDRESS,
            new OctetString(''));
        $this->expectException(\UnexpectedValueException::class);
        IPAddress::fromASN1($el);
    }
}
