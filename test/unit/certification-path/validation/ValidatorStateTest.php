<?php

declare(strict_types=1);

use ASN1\Type\Primitive\NullType;
use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;
use X509\CertificationPath\PathValidation\PathValidationConfig;
use X509\CertificationPath\PathValidation\ValidatorState;

/**
 * @group certification-path
 */
class ValidatorStateTest extends PHPUnit_Framework_TestCase
{
    private static $_ca;
    
    public static function setUpBeforeClass()
    {
        self::$_ca = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_ca = null;
    }
    
    public function testInitialize()
    {
        $state = ValidatorState::initialize(
            PathValidationConfig::defaultConfig(), self::$_ca, 3);
        $this->assertInstanceOf(ValidatorState::class, $state);
        return $state;
    }
    
    /**
     * @depends testInitialize
     * @expectedException LogicException
     *
     * @param ValidatorState $state
     */
    public function testValidPolicyTreeFail(ValidatorState $state)
    {
        $state->withoutValidPolicyTree()->validPolicyTree();
    }
    
    /**
     * @depends testInitialize
     *
     * @param ValidatorState $state
     */
    public function testWorkingPublicKeyParameters(ValidatorState $state)
    {
        $this->assertInstanceOf(NullType::class,
            $state->workingPublicKeyParameters());
    }
}
