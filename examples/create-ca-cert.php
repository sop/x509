<?php
/**
 * Create certification authority certificate.
 *
 * php create-ca-cert.php
 */

use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\KeyUsageExtension;
use X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use X509\Certificate\Extensions;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;

require dirname(__DIR__) . "/vendor/autoload.php";

// load private key from PEM
$private_key_info = PrivateKeyInfo::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/test/assets/rsa/private_key.pem"));
// extract public key from private key
$public_key_info = $private_key_info->privateKey()
	->publicKey()
	->publicKeyInfo();
// DN of the certification authority
$name = Name::fromString("cn=Example CA");
// validity period
$validity = Validity::fromStrings("now", "now + 10 years");
// create "to be signed" certificate object with extensions
$tbs_cert = new TBSCertificate($name, $public_key_info, $name, $validity);
$tbs_cert = $tbs_cert->withExtensions(
	new Extensions(new BasicConstraintsExtension(true, true), 
		new SubjectKeyIdentifierExtension(false, 
			$public_key_info->keyIdentifier()), 
		new KeyUsageExtension(true, 
			KeyUsageExtension::DIGITAL_SIGNATURE |
				 KeyUsageExtension::KEY_CERT_SIGN)));
// sign certificate with private key
$algo = new SHA256WithRSAEncryptionAlgorithmIdentifier();
$cert = $tbs_cert->sign(Crypto::getDefault(), $algo, $private_key_info);
echo $cert;
