<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;

abstract class RefExtTestHelper extends TestCase
{
    protected static $_extensions;

    public static function setUpBeforeClass(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        $cert = Certificate::fromPEM($pem);
        self::$_extensions = $cert->tbsCertificate()->extensions();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_extensions = null;
    }
}
