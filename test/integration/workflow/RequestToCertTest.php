<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @group workflow
 *
 * @internal
 */
class RequestToCertTest extends TestCase
{
    private static $_issuerKey;

    private static $_subjectKey;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerKey = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        self::$_subjectKey = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerKey = null;
        self::$_subjectKey = null;
    }

    public function testCreateCA()
    {
        $name = Name::fromString('cn=Issuer');
        $validity = Validity::fromStrings('2016-05-02 12:00:00',
            '2016-05-03 12:00:00');
        $pki = self::$_issuerKey->publicKeyInfo();
        $tbs_cert = new TBSCertificate($name, $pki, $name, $validity);
        $tbs_cert = $tbs_cert->withExtensions(
            new Extensions(new BasicConstraintsExtension(true, true),
                new SubjectKeyIdentifierExtension(false, $pki->keyIdentifier()),
                new KeyUsageExtension(true,
                    KeyUsageExtension::DIGITAL_SIGNATURE |
                         KeyUsageExtension::KEY_CERT_SIGN)));
        $algo = new SHA256WithRSAEncryptionAlgorithmIdentifier();
        $cert = $tbs_cert->sign($algo, self::$_issuerKey);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    public function testCreateRequest()
    {
        $subject = Name::fromString('cn=Subject');
        $pkinfo = self::$_subjectKey->publicKeyInfo();
        $cri = new CertificationRequestInfo($subject, $pkinfo);
        $cri = $cri->withExtensionRequest(
            new Extensions(new BasicConstraintsExtension(true, false)));
        $algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $csr = $cri->sign($algo, self::$_subjectKey);
        $this->assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    /**
     * @depends testCreateRequest
     * @depends testCreateCA
     *
     * @param CertificationRequest $csr
     * @param Certificate          $ca_cert
     */
    public function testIssueCertificate(CertificationRequest $csr,
        Certificate $ca_cert)
    {
        $tbs_cert = TBSCertificate::fromCSR($csr)->withIssuerCertificate(
            $ca_cert);
        $validity = Validity::fromStrings('2016-05-02 12:00:00',
            '2016-05-02 13:00:00');
        $tbs_cert = $tbs_cert->withValidity($validity);
        $tbs_cert = $tbs_cert->withAdditionalExtensions(
            new KeyUsageExtension(true,
                KeyUsageExtension::DIGITAL_SIGNATURE |
                     KeyUsageExtension::KEY_ENCIPHERMENT),
            new BasicConstraintsExtension(true, false));
        $algo = new SHA512WithRSAEncryptionAlgorithmIdentifier();
        $cert = $tbs_cert->sign($algo, self::$_issuerKey);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends testCreateCA
     * @depends testIssueCertificate
     *
     * @param Certificate $ca
     * @param Certificate $cert
     */
    public function testBuildPath(Certificate $ca, Certificate $cert)
    {
        $path = CertificationPath::fromTrustAnchorToTarget($ca, $cert);
        $this->assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends testBuildPath
     *
     * @param CertificationPath $path
     */
    public function testValidatePath(CertificationPath $path)
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(
            new DateTimeImmutable('2016-05-02 12:30:00'));
        $result = $path->validate($config);
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }
}
