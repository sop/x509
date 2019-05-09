<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\Certificate\Certificate;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group ac
 *
 * @internal
 */
class HolderIntegrationTest extends TestCase
{
    private static $_pkc;

    public static function setUpBeforeClass(): void
    {
        self::$_pkc = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pkc = null;
    }

    public function testIdentifiesPKCSimple()
    {
        $holder = Holder::fromPKC(self::$_pkc);
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCByEntityName()
    {
        $gn = new GeneralNames(
            new DirectoryName(self::$_pkc->tbsCertificate()->subject()));
        $holder = new Holder(null, $gn);
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCByEntityNameSANDirectoryName()
    {
        $gn = new GeneralNames(
            DirectoryName::fromDNString(
                'o=ACME Alternative Ltd., c=FI, cn=alt.example.com'));
        $holder = new Holder(null, $gn);
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCNoIdentifiers()
    {
        $holder = new Holder();
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCNoCertIdMatch()
    {
        $is = new IssuerSerial(
            new GeneralNames(DirectoryName::fromDNString('cn=Fail')), 1);
        $holder = new Holder($is);
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCNoEntityNameMatch()
    {
        $gn = new GeneralNames(DirectoryName::fromDNString('cn=Fail'));
        $holder = new Holder(null, $gn);
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }
}
