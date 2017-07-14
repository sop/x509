<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use X509\AttributeCertificate\IssuerSerial;
use X509\Certificate\UniqueIdentifier;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;

/**
 * @group ac
 */
class IssuerSerialTest extends PHPUnit_Framework_TestCase
{
    private static $_issuer;
    
    private static $_uid;
    
    public static function setUpBeforeClass()
    {
        self::$_issuer = new GeneralNames(DirectoryName::fromDNString("cn=Test"));
        self::$_uid = new UniqueIdentifier(new BitString(hex2bin("ff")));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_issuer = null;
        self::$_uid = null;
    }
    
    public function testCreate()
    {
        $iss_ser = new IssuerSerial(self::$_issuer, 1, self::$_uid);
        $this->assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }
    
    /**
     * @depends testCreate
     *
     * @param IssuerSerial $iss_ser
     */
    public function testEncode(IssuerSerial $iss_ser)
    {
        $seq = $iss_ser->toASN1();
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
        $iss_ser = IssuerSerial::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param IssuerSerial $ref
     * @param IssuerSerial $new
     */
    public function testRecoded(IssuerSerial $ref, IssuerSerial $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testIssuer(IssuerSerial $is)
    {
        $this->assertEquals(self::$_issuer, $is->issuer());
    }
    
    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testSerial(IssuerSerial $is)
    {
        $this->assertEquals(1, $is->serial());
    }
    
    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testIssuerUID(IssuerSerial $is)
    {
        $this->assertEquals(self::$_uid, $is->issuerUID());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testNoIssuerUIDFail()
    {
        $is = new IssuerSerial(self::$_issuer, 1);
        $is->issuerUID();
    }
}
