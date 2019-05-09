<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\Exception\PathValidationException;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;
use Sop\X509\CertificationPath\PathValidation\PathValidator;

/**
 * @group certification-path
 *
 * @internal
 */
class CertificationPathValidationTest extends TestCase
{
    /**
     * @var CertificationPath
     */
    private static $_path;

    public static function setUpBeforeClass(): void
    {
        $certs = [
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem')),
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-ecdsa.pem')),
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem')), ];
        self::$_path = new CertificationPath(...$certs);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_path = null;
    }

    /**
     * @return PathValidationResult
     */
    public function testValidateDefault()
    {
        $result = self::$_path->validate(PathValidationConfig::defaultConfig());
        $this->assertInstanceOf(PathValidationResult::class, $result);
        return $result;
    }

    /**
     * @depends testValidateDefault
     *
     * @param PathValidationResult $result
     */
    public function testResult(PathValidationResult $result)
    {
        $expected_cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $this->assertEquals($expected_cert, $result->certificate());
    }

    public function testValidateExpired()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(
            new DateTimeImmutable('2026-01-03'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    public function testValidateNotBeforeFail()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(
            new DateTimeImmutable('2015-12-31'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    public function testValidatePathLengthFail()
    {
        $config = PathValidationConfig::defaultConfig()->withMaxLength(0);
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    public function testNoCertsFail()
    {
        $this->expectException(\LogicException::class);
        new PathValidator(Crypto::getDefault(),
            PathValidationConfig::defaultConfig());
    }

    public function testExplicitTrustAnchor()
    {
        $config = PathValidationConfig::defaultConfig()->withTrustAnchor(
            self::$_path->certificates()[0]);
        $validator = new PathValidator(Crypto::getDefault(), $config,
            ...self::$_path->certificates());
        $this->assertInstanceOf(PathValidationResult::class,
            $validator->validate());
    }

    public function testValidateFailNoCerts()
    {
        $validator = new PathValidator(Crypto::getDefault(),
            PathValidationConfig::defaultConfig(),
            ...self::$_path->certificates());
        $cls = new ReflectionClass($validator);
        $prop = $cls->getProperty('_certificates');
        $prop->setAccessible(true);
        $prop->setValue($validator, []);
        $this->expectException(\LogicException::class);
        $validator->validate();
    }
}
