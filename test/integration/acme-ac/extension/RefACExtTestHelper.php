<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use X509\AttributeCertificate\AttributeCertificate;

abstract class RefACExtTestHelper extends \PHPUnit\Framework\TestCase
{
    protected static $_extensions;
    
    public static function setUpBeforeClass()
    {
        $ac = AttributeCertificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/ac/acme-ac.pem"));
        self::$_extensions = $ac->acinfo()->extensions();
    }
    
    public static function tearDownAfterClass()
    {
        self::$_extensions = null;
    }
}
