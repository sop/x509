<?php
/**
 * Validate certification path.
 *
 * php path-validate.php
 */

use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X509\Certificate\Certificate;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;

require dirname(__DIR__) . "/vendor/autoload.php";

// generate CA and end-entity certificates
$dir = __DIR__;
$ca_pem = `php "$dir/create-ca-cert.php"`;
$csr_pem = `php "$dir/create-csr.php"`;
$ca_file = tempnam(sys_get_temp_dir(), "cert");
file_put_contents($ca_file, $ca_pem);
$csr_file = tempnam(sys_get_temp_dir(), "csr");
file_put_contents($csr_file, $csr_pem);
$cert_pem = `php "$dir/issue-cert.php" $ca_file $csr_file`;
// load CA certificate
$ca = Certificate::fromPEM(PEM::fromString($ca_pem));
// load end-entity certificate
$cert = Certificate::fromPEM(PEM::fromString($cert_pem));
// build certification path from CA to end-entity certificate
$path = CertificationPath::fromTrustAnchorToTarget($ca, $cert);
foreach ($path as $idx => $cert) {
	echo "#$idx: " . $cert->tbsCertificate()->subject() . "\n";
}
// validate certification path with default configuration
$config = PathValidationConfig::defaultConfig();
$result = $path->validate(Crypto::getDefault(), $config);
echo "Certificate '" . $result->certificate()
	->tbsCertificate()
	->subject() . "' is valid\n";
// remove temporary files
unlink($ca_file);
unlink($csr_file);
