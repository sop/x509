<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Attribute;
use X509\AttributeCertificate\AttCertValidityPeriod;
use X509\AttributeCertificate\Attribute\AccessIdentityAttribute;
use X509\AttributeCertificate\Attribute\AuthenticationInfoAttribute;
use X509\AttributeCertificate\Attribute\ChargingIdentityAttribute;
use X509\AttributeCertificate\Attribute\GroupAttribute;
use X509\AttributeCertificate\Attribute\IetfAttrValue;
use X509\AttributeCertificate\Attribute\RoleAttribute;
use X509\AttributeCertificate\AttributeCertificateInfo;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Holder;
use X509\AttributeCertificate\IssuerSerial;
use X509\AttributeCertificate\V2Form;
use X509\Certificate\Certificate;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\Certificate\Extension\NoRevocationAvailableExtension;
use X509\Certificate\Extension\Target\TargetName;
use X509\Certificate\Extension\Target\Targets;
use X509\Certificate\Extension\TargetInformationExtension;
use X509\Certificate\Extensions;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\DNSName;
use X509\GeneralName\UniformResourceIdentifier;
use X509\GeneralName\GeneralNames;
use CryptoUtil\Crypto\Crypto;

require_once dirname(dirname(dirname(__DIR__))) . "/vendor/autoload.php";

// load issuer certificate
$issuer_cert = Certificate::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/certs/acme-rsa.pem"));
// load issuer private and public keys
$issuer_private_key = PrivateKey::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/certs/keys/acme-rsa.pem"))->privateKeyInfo();
$issuer_public_key = $issuer_private_key->privateKey()
	->publicKey()
	->publicKeyInfo();
// load AC holder certificate
$holder_cert = Certificate::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/certs/acme-ecdsa.pem"));

$holder = new Holder(IssuerSerial::fromCertificate($holder_cert), 
	new GeneralNames(
		new DirectoryName($holder_cert->tbsCertificate()->subject())));
$issuer = new V2Form(
	new GeneralNames(
		new DirectoryName($issuer_cert->tbsCertificate()->subject())));
$validity = AttCertValidityPeriod::fromStrings("2016-01-01 12:00:00", 
	"2016-03-01 12:00:00", "UTC");
$authinfo_attr = new AuthenticationInfoAttribute(
	new UniformResourceIdentifier("urn:service"), 
	DirectoryName::fromDNString("cn=username"), "password");
$authid_attr = new AccessIdentityAttribute(
	new UniformResourceIdentifier("urn:service"), 
	DirectoryName::fromDNString("cn=username"));
$charge_attr = new ChargingIdentityAttribute(
	new GeneralNames(DirectoryName::fromDNString("cn=ACME Ltd.")), 
	IetfAttrValue::fromString("ACME Ltd."));
$group_attr = new GroupAttribute(null, IetfAttrValue::fromString("group1"), 
	IetfAttrValue::fromString("group2"));
$role_attr = Attribute::fromAttributeValues(
	new RoleAttribute(new UniformResourceIdentifier("urn:role1")), 
	new RoleAttribute(new UniformResourceIdentifier("urn:role2")));
$attribs = new Attributes($authinfo_attr->attribute(), $authid_attr->attribute(), 
	$charge_attr->attribute(), $group_attr->attribute(), $role_attr);
$aki_ext = new AuthorityKeyIdentifierExtension(false, 
	$issuer_public_key->keyIdentifier());
$ti_ext = new TargetInformationExtension(true, 
	new Targets(new TargetName(new UniformResourceIdentifier("urn:test")), 
		new TargetName(new DNSName("*.example.com"))), 
	new Targets(new TargetName(new UniformResourceIdentifier("urn:another"))));
$nra_ext = new NoRevocationAvailableExtension(false);
$extensions = new Extensions($aki_ext, $nra_ext, $ti_ext);
$aci = new AttributeCertificateInfo($holder, $issuer, $validity, $attribs);
$aci = $aci->withSerial(0xbadcafe);
$aci = $aci->withExtensions($extensions);
$ac = $aci->sign(Crypto::getDefault(), 
	new SHA256WithRSAEncryptionAlgorithmIdentifier(), $issuer_private_key);
echo $ac;
