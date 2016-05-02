<?php
/**
 * Create certification request.
 *
 * php create-csr.php
 */

use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\CertificationRequest\CertificationRequestInfo;

require dirname(__DIR__) . "/vendor/autoload.php";

$private_key_info = PrivateKeyInfo::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/test/assets/ec/private_key.pem"));
$public_key_info = $private_key_info->privateKey()
	->publicKey()
	->publicKeyInfo();
$subject = Name::fromString("cn=example.com, O=Example\, Inc., C=US");
$cri = new CertificationRequestInfo($subject, $public_key_info);
$algo = new ECDSAWithSHA1AlgorithmIdentifier();
$csr = $cri->sign(Crypto::getDefault(), $algo, $private_key_info);
echo $csr;
