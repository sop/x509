<?php
use ASN1\Type\Constructed\Sequence;
use X509\AttributeCertificate\AttCertValidityPeriod;

/**
 * @group ac
 */
class AttCertValidityPeriodTest extends PHPUnit_Framework_TestCase
{
    private static $_nb;
    
    private static $_na;
    
    public static function setUpBeforeClass()
    {
        self::$_nb = new DateTimeImmutable("2016-05-17 12:00:00");
        self::$_na = new DateTimeImmutable("2016-05-17 13:00:00");
    }
    
    public static function tearDownAfterClass()
    {
        self::$_nb = null;
        self::$_nb = null;
    }
    
    public function testCreate()
    {
        $validity = new AttCertValidityPeriod(self::$_nb, self::$_na);
        $this->assertInstanceOf(AttCertValidityPeriod::class, $validity);
        return $validity;
    }
    
    /**
     * @depends testCreate
     *
     * @param AttCertValidityPeriod $validity
     */
    public function testEncode(AttCertValidityPeriod $validity)
    {
        $seq = $validity->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $iss_ser = AttCertValidityPeriod::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(AttCertValidityPeriod::class, $iss_ser);
        return $iss_ser;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param AttCertValidityPeriod $ref
     * @param AttCertValidityPeriod $new
     */
    public function testRecoded(AttCertValidityPeriod $ref,
        AttCertValidityPeriod $new)
    {
        $this->assertEquals($ref->notBeforeTime()
            ->getTimestamp(), $new->notBeforeTime()
            ->getTimestamp());
        $this->assertEquals($ref->notAfterTime()
            ->getTimestamp(), $new->notAfterTime()
            ->getTimestamp());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttCertValidityPeriod $validity
     */
    public function testNotBefore(AttCertValidityPeriod $validity)
    {
        $this->assertEquals(self::$_nb, $validity->notBeforeTime());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttCertValidityPeriod $validity
     */
    public function testNotAfter(AttCertValidityPeriod $validity)
    {
        $this->assertEquals(self::$_na, $validity->notAfterTime());
    }
    
    public function testFromStrings()
    {
        $validity = AttCertValidityPeriod::fromStrings("now", "now + 1 day",
            "UTC");
        $this->assertInstanceOf(AttCertValidityPeriod::class, $validity);
    }
}
