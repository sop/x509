<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use X501\ASN1\Name;
use X509\AttributeCertificate\AttCertIssuer;
use X509\Certificate\Certificate;

/**
 * @group ac
 */
class AttCertIssuerIntegrationTest extends \PHPUnit\Framework\TestCase
{
    private static $_pkc;
    
    public static function setUpBeforeClass()
    {
        self::$_pkc = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_pkc = null;
    }
    
    public function testIdentifiesPKC()
    {
        $iss = AttCertIssuer::fromPKC(self::$_pkc);
        $this->assertTrue($iss->identifiesPKC(self::$_pkc));
    }
    
    public function testIdentifiesPKCMismatch()
    {
        $iss = AttCertIssuer::fromName(Name::fromString("cn=Fail"));
        $this->assertFalse($iss->identifiesPKC(self::$_pkc));
    }
}
