<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\AttributeCertificate\AttributeCertificate;

abstract class RefACExtTestHelper extends TestCase
{
    protected static $_extensions;

    public static function setUpBeforeClass(): void
    {
        $ac = AttributeCertificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem'));
        self::$_extensions = $ac->acinfo()->extensions();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_extensions = null;
    }
}
