<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\Certificate\CertificateChain;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * @group certification-path
 *
 * @internal
 */
class CertificationPathTest extends TestCase
{
    private static $_certs;

    public static function setUpBeforeClass(): void
    {
        self::$_certs = [
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem')),
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem')),
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem')), ];
    }

    public static function tearDownAfterClass(): void
    {
        self::$_certs = null;
    }

    public function testCreate()
    {
        $path = new CertificationPath(...self::$_certs);
        $this->assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testCount(CertificationPath $path)
    {
        $this->assertCount(3, $path);
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testIterator(CertificationPath $path)
    {
        $values = [];
        foreach ($path as $cert) {
            $values[] = $cert;
        }
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testValidate(CertificationPath $path)
    {
        $result = $path->validate(PathValidationConfig::defaultConfig());
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }

    public function testFromTrustAnchorToTarget()
    {
        $path = CertificationPath::fromTrustAnchorToTarget(self::$_certs[0],
            self::$_certs[2], new CertificateBundle(...self::$_certs));
        $this->assertInstanceOf(CertificationPath::class, $path);
    }

    public function testFromCertificateChain()
    {
        $chain = new CertificateChain(...array_reverse(self::$_certs, false));
        $path = CertificationPath::fromCertificateChain($chain);
        $this->assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends testCreate
     * @depends testFromCertificateChain
     *
     * @param CertificationPath $ref
     * @param CertificationPath $path
     */
    public function testFromChainEquals(CertificationPath $ref,
        CertificationPath $path)
    {
        $this->assertEquals($ref, $path);
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testTrustAnchor(CertificationPath $path)
    {
        $cert = $path->trustAnchorCertificate();
        $this->assertEquals(self::$_certs[0], $cert);
    }

    public function testTrustAnchorFail()
    {
        $path = new CertificationPath();
        $this->expectException(\LogicException::class);
        $path->trustAnchorCertificate();
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testEndEntity(CertificationPath $path)
    {
        $cert = $path->endEntityCertificate();
        $this->assertEquals(self::$_certs[2], $cert);
    }

    public function testEndEntityFail()
    {
        $path = new CertificationPath();
        $this->expectException(\LogicException::class);
        $path->endEntityCertificate();
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testCertificateChain(CertificationPath $path)
    {
        $chain = $path->certificateChain();
        $this->assertInstanceOf(CertificateChain::class, $chain);
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testStartWithSingle(CertificationPath $path)
    {
        $this->assertTrue($path->startsWith(self::$_certs[0]));
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testStartWithMulti(CertificationPath $path)
    {
        $this->assertTrue(
            $path->startsWith(...array_slice(self::$_certs, 0, 2, false)));
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testStartWithAll(CertificationPath $path)
    {
        $this->assertTrue($path->startsWith(...self::$_certs));
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testStartWithTooManyFail(CertificationPath $path)
    {
        $this->assertFalse(
            $path->startsWith(
                ...array_merge(self::$_certs, [self::$_certs[0]])));
    }

    /**
     * @depends testCreate
     *
     * @param CertificationPath $path
     */
    public function testStartWithFail(CertificationPath $path)
    {
        $this->assertFalse($path->startsWith(self::$_certs[1]));
    }
}
