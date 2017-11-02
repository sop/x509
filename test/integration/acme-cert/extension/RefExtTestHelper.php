<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;

abstract class RefExtTestHelper extends PHPUnit_Framework_TestCase
{
    protected static $_extensions;
    
    public static function setUpBeforeClass()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem");
        $cert = Certificate::fromPEM($pem);
        self::$_extensions = $cert->tbsCertificate()->extensions();
    }
    
    public static function tearDownAfterClass()
    {
        self::$_extensions = null;
    }
}
