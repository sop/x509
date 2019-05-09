<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group general-name
 *
 * @internal
 */
class GeneralNameTest extends TestCase
{
    public function testInvalidTagFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        GeneralName::fromASN1(new ImplicitlyTaggedType(9, new NullType()));
    }

    public function testFromChosenBadCall()
    {
        $this->expectException(\BadMethodCallException::class);
        GeneralName::fromChosenASN1(new UnspecifiedType(new NullType()));
    }

    public function testEquals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:1');
        $this->assertTrue($n1->equals($n2));
    }

    public function testNotEquals()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new UniformResourceIdentifier('urn:2');
        $this->assertFalse($n1->equals($n2));
    }

    public function testNotEqualsDifferentTypes()
    {
        $n1 = new UniformResourceIdentifier('urn:1');
        $n2 = new DNSName('test');
        $this->assertFalse($n1->equals($n2));
    }
}
