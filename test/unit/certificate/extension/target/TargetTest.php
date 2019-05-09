<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\RFC822Name;

/**
 * @group certificate
 * @group extension
 * @group target
 *
 * @internal
 */
class TargetTest extends TestCase
{
    public function testFromASN1BadCall()
    {
        $this->expectException(\BadMethodCallException::class);
        Target::fromChosenASN1(new ImplicitlyTaggedType(0, new NullType()));
    }

    public function testDecodeTargetCertUnsupportedFail()
    {
        $this->expectException(\RuntimeException::class);
        Target::fromASN1(
            new ImplicitlyTaggedType(Target::TYPE_CERT, new NullType()));
    }

    public function testDecodeUnsupportedTagFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        Target::fromASN1(new ImplicitlyTaggedType(3, new NullType()));
    }

    public function testEquals()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new DNSName('n1'));
        $this->assertTrue($t1->equals($t2));
    }

    public function testNotEquals()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new DNSName('n2'));
        $this->assertFalse($t1->equals($t2));
    }

    public function testNotEqualsDifferentEncoding()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetName(new RFC822Name('n2'));
        $this->assertFalse($t1->equals($t2));
    }

    public function testNotEqualsDifferentType()
    {
        $t1 = new TargetName(new DNSName('n1'));
        $t2 = new TargetGroup(new DNSName('n1'));
        $this->assertFalse($t1->equals($t2));
    }
}
