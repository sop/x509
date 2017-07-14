<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\CertificatePolicy\CPSQualifier;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 */
class CPSQualifierTest extends PHPUnit_Framework_TestCase
{
    const URI = "urn:test";
    
    public function testCreate()
    {
        $qual = new CPSQualifier(self::URI);
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }
    
    /**
     * @depends testCreate
     *
     * @param CPSQualifier $qual
     */
    public function testEncode(CPSQualifier $qual)
    {
        $el = $qual->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $qual = CPSQualifier::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param CPSQualifier $ref
     * @param CPSQualifier $new
     */
    public function testRecoded(CPSQualifier $ref, CPSQualifier $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param CPSQualifier $qual
     */
    public function testURI(CPSQualifier $qual)
    {
        $this->assertEquals(self::URI, $qual->uri());
    }
    
    /**
     * @depends testCreate
     *
     * @param CPSQualifier $qual
     */
    public function testOID(CPSQualifier $qual)
    {
        $this->assertEquals(CPSQualifier::OID_CPS, $qual->oid());
    }
}
