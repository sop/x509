<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\Enumerated;
use ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use X509\AttributeCertificate\ObjectDigestInfo;

/**
 * @group ac
 */
class ObjectDigestInfoTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $odi = new ObjectDigestInfo(ObjectDigestInfo::TYPE_PUBLIC_KEY,
            new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            new BitString(hex2bin("ff")));
        $this->assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }
    
    /**
     * @depends testCreate
     *
     * @param ObjectDigestInfo $odi
     */
    public function testEncode(ObjectDigestInfo $odi)
    {
        $seq = $odi->toASN1();
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
        $odi = ObjectDigestInfo::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param ObjectDigestInfo $ref
     * @param ObjectDigestInfo $new
     */
    public function testRecoded(ObjectDigestInfo $ref, ObjectDigestInfo $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    public function testDecodeWithOtherObjectTypeID()
    {
        $algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $seq = new Sequence(
            new Enumerated(ObjectDigestInfo::TYPE_OTHER_OBJECT_TYPES),
            new ObjectIdentifier("1.3.6.1.3"), $algo->toASN1(), new BitString(""));
        $odi = ObjectDigestInfo::fromASN1($seq);
        $this->assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }
    
    /**
     * @depends testDecodeWithOtherObjectTypeID
     *
     * @param ObjectDigestInfo $odi
     */
    public function testEncodeWithOtherObjectTypeID(ObjectDigestInfo $odi)
    {
        $seq = $odi->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
    }
}
