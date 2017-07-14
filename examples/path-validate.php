<?php
/**
 * Validate certification path.
 *
 * php path-validate.php
 */

use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;

require dirname(__DIR__) . "/vendor/autoload.php";

// generate CA and end-entity certificates
$dir = __DIR__;
$ca_pem = `php '$dir/create-ca-cert.php'`;
$csr_pem = `php '$dir/create-csr.php'`;
$ca_file = tempnam(sys_get_temp_dir(), "crt");
file_put_contents($ca_file, $ca_pem);
$csr_file = tempnam(sys_get_temp_dir(), "csr");
file_put_contents($csr_file, $csr_pem);
$cert_pem = `php '$dir/issue-cert.php' '$ca_file' '$csr_file'`;
// load CA certificate
$ca = Certificate::fromPEM(PEM::fromString($ca_pem));
// load end-entity certificate
$cert = Certificate::fromPEM(PEM::fromString($cert_pem));
// build certification path from CA to end-entity certificate
$path = CertificationPath::fromTrustAnchorToTarget($ca, $cert);
foreach ($path->certificates() as $idx => $cert) {
    printf("#%d: %s\n", $idx,
        $cert->tbsCertificate()
            ->subject()
            ->toString());
}
// validate certification path with default configuration
$config = PathValidationConfig::defaultConfig();
$result = $path->validate($config);
printf("Certificate '%s' is valid.\n",
    $result->certificate()
        ->tbsCertificate()
        ->subject()
        ->toString());
// remove temporary files
unlink($ca_file);
unlink($csr_file);
