<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateChain;
use X509\CertificationPath\CertificationPath;

/**
 * @group certificate
 */
class CertificateChainTest extends PHPUnit_Framework_TestCase
{
    private static $_pems;
    
    private static $_certs;
    
    public static function setUpBeforeClass()
    {
        self::$_pems = array(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"),
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-interm-rsa.pem"),
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
        self::$_certs = array_map(
            function (PEM $pem) {
                return Certificate::fromPEM($pem);
            }, self::$_pems);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_pems = null;
        self::$_certs = null;
    }
    
    public function testCreateChain()
    {
        $chain = new CertificateChain(...self::$_certs);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testCertificates(CertificateChain $chain)
    {
        $certs = $chain->certificates();
        $this->assertContainsOnlyInstancesOf(Certificate::class, $chain);
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testEndEntityCert(CertificateChain $chain)
    {
        $this->assertEquals(self::$_certs[0], $chain->endEntityCertificate());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testEndEntityCertFail()
    {
        $chain = new CertificateChain();
        $chain->endEntityCertificate();
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testTrustAnchorCert(CertificateChain $chain)
    {
        $this->assertEquals(self::$_certs[2], $chain->trustAnchorCertificate());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testTrustAnchorCertFail()
    {
        $chain = new CertificateChain();
        $chain->trustAnchorCertificate();
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testCount(CertificateChain $chain)
    {
        $this->assertCount(3, $chain);
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testIterator(CertificateChain $chain)
    {
        $certs = array();
        foreach ($chain as $cert) {
            $certs[] = $cert;
        }
        $this->assertContainsOnlyInstancesOf(Certificate::class, $certs);
    }
    
    public function testFromPEMs()
    {
        $chain = CertificateChain::fromPEMs(...self::$_pems);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }
    
    /**
     * @depends testCreateChain
     * @depends testFromPEMs
     *
     * @param CertificateChain $ref
     * @param CertificateChain $chain
     */
    public function testFromPEMEquals(CertificateChain $ref,
        CertificateChain $chain)
    {
        $this->assertEquals($ref, $chain);
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testToPEMString(CertificateChain $chain)
    {
        $expected = sprintf("%s\n%s\n%s", self::$_pems[0], self::$_pems[1],
            self::$_pems[2]);
        $str = $chain->toPEMString();
        $this->assertEquals($expected, $str);
        return $str;
    }
    
    /**
     * @depends testToPEMString
     *
     * @param string $str
     */
    public function testFromPEMString($str)
    {
        $chain = CertificateChain::fromPEMString($str);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }
    
    /**
     * @depends testCreateChain
     * @depends testFromPEMString
     *
     * @param CertificateChain $ref
     * @param CertificateChain $chain
     */
    public function testFromPEMStringEquals(CertificateChain $ref,
        CertificateChain $chain)
    {
        $this->assertEquals($ref, $chain);
    }
    
    /**
     * @depends testCreateChain
     *
     * @param CertificateChain $chain
     */
    public function testCertificationPath(CertificateChain $chain)
    {
        $path = $chain->certificationPath();
        $this->assertInstanceOf(CertificationPath::class, $path);
    }
}
