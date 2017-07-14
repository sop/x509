<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\CertificatePolicy\DisplayText;
use X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 */
class UserNoticeQualifierTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $qual = new UserNoticeQualifier(DisplayText::fromString("test"),
            new NoticeReference(DisplayText::fromString("org"), 1, 2, 3));
        $this->assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }
    
    /**
     * @depends testCreate
     *
     * @param UserNoticeQualifier $qual
     */
    public function testEncode(UserNoticeQualifier $qual)
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
        $qual = UserNoticeQualifier::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param UserNoticeQualifier $ref
     * @param UserNoticeQualifier $new
     */
    public function testRecoded(UserNoticeQualifier $ref,
        UserNoticeQualifier $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param UserNoticeQualifier $qual
     */
    public function testExplicitText(UserNoticeQualifier $qual)
    {
        $this->assertInstanceOf(DisplayText::class, $qual->explicitText());
    }
    
    /**
     * @depends testCreate
     *
     * @param UserNoticeQualifier $qual
     */
    public function testNoticeRef(UserNoticeQualifier $qual)
    {
        $this->assertInstanceOf(NoticeReference::class, $qual->noticeRef());
    }
    public function testCreateEmpty()
    {
        $qual = new UserNoticeQualifier();
        $this->assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param UserNoticeQualifier $qual
     */
    public function testExplicitTextFail(UserNoticeQualifier $qual)
    {
        $qual->explicitText();
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param UserNoticeQualifier $qual
     */
    public function testNoticeRefFail(UserNoticeQualifier $qual)
    {
        $qual->noticeRef();
    }
}
