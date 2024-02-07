<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;

/**
 * @group certificate
 * @group extension
 * @group logotype
 *
 * @internal
 */
class DeEncodeTest extends TestCase
{
    /**
     * @return array<string,Certificate>
     */
    public function testDecode(): array
    {
        $certFilesDir = TEST_ASSETS_DIR . '/certs/with-logotype-extension';
        $certFiles = scandir($certFilesDir);

        $result = [];

        foreach ($certFiles as $certFilename) {
            if ('pem' == strtolower(pathinfo($certFilename, PATHINFO_EXTENSION))) {
                $pem = PEM::fromFile("{$certFilesDir}/{$certFilename}");
                $result[$pem->string()] = Certificate::fromPEM($pem);
            }
        }

        $this->assertGreaterThan(0, count($result));

        return $result;
    }

    /**
     * @depends testDecode
     *
     * @param array<string,Certificate> $certsDecoded
     */
    public function testEncode(array $certsDecoded)
    {
        foreach ($certsDecoded as $sourcePem => $cert) {
            $certEncoded = $cert->toPEM();
            $this->assertEquals($sourcePem, $certEncoded);
        }
    }
}
