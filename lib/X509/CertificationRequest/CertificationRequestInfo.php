<?php

namespace X509\CertificationRequest;

use ASN1\DERData;
use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;


/**
 * Implements <i>CertificationRequestInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2986#section-4
 */
class CertificationRequestInfo
{
	const VERSION_1 = 0;
	
	/**
	 * Version.
	 *
	 * @var int
	 */
	protected $_version;
	
	/**
	 * Subject.
	 *
	 * @var Name $_subject
	 */
	protected $_subject;
	
	/**
	 * Public key info.
	 *
	 * @var PublicKeyInfo $_subjectPKInfo
	 */
	protected $_subjectPKInfo;
	
	/**
	 * Attributes.
	 *
	 * @var Attributes $_attributes
	 */
	protected $_attributes;
	
	/**
	 * Constructor
	 *
	 * @param Name $subject Subject
	 * @param PublicKeyInfo $pkinfo Public key info
	 */
	public function __construct(Name $subject, PublicKeyInfo $pkinfo) {
		$this->_version = self::VERSION_1;
		$this->_subject = $subject;
		$this->_subjectPKInfo = $pkinfo;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$version = $seq->at(0, Element::TYPE_INTEGER)->number();
		if ($version != self::VERSION_1) {
			throw new \UnexpectedValueException(
				"Version #$version not supported");
		}
		$subject = Name::fromASN1($seq->at(1, Element::TYPE_SEQUENCE));
		$pkinfo = PublicKeyInfo::fromASN1($seq->at(2, Element::TYPE_SEQUENCE));
		$obj = new self($subject, $pkinfo);
		if ($seq->hasTagged(0)) {
			$obj->_attributes = Attributes::fromASN1(
				$seq->getTagged(0)->implicit(Element::TYPE_SET));
		}
		return $obj;
	}
	
	/**
	 * Get version.
	 *
	 * @return int
	 */
	public function version() {
		return $this->_version;
	}
	
	/**
	 * Get subject.
	 *
	 * @return Name
	 */
	public function subject() {
		return $this->_subject;
	}
	
	/**
	 * Get subject public key info.
	 *
	 * @return PublicKeyInfo
	 */
	public function subjectPKInfo() {
		return $this->_subjectPKInfo;
	}
	
	/**
	 * Whether certification request info has attributes.
	 *
	 * @return bool
	 */
	public function hasAttributes() {
		return isset($this->_attributes);
	}
	
	/**
	 * Get attributes.
	 *
	 * @throws \LogicException
	 * @return Attributes
	 */
	public function attributes() {
		if (!$this->hasAttributes()) {
			throw new \LogicException("No attributes");
		}
		return $this->_attributes;
	}
	
	/**
	 * Get instance of self with attributes.
	 *
	 * @param Attributes $attribs
	 */
	public function withAttributes(Attributes $attribs) {
		$obj = clone $this;
		$obj->_attributes = $attribs;
		return $obj;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array(new Integer($this->_version), 
			$this->_subject->toASN1(), $this->_subjectPKInfo->toASN1());
		if (isset($this->_attributes)) {
			$elements[] = new ImplicitlyTaggedType(0, 
				$this->_attributes->toASN1());
		}
		return new Sequence(...$elements);
	}
	
	/**
	 * Create signed CertificationRequest.
	 *
	 * @param Crypto $crypto Crypto engine
	 * @param SignatureAlgorithmIdentifier $algo Algorithm used for signing
	 * @param PrivateKey $private_key Private key used for signing
	 * @return PEM
	 */
	public function sign(Crypto $crypto, SignatureAlgorithmIdentifier $algo, 
			PrivateKeyInfo $privkey_info) {
		$data = $this->toASN1()->toDER();
		$signature = $crypto->sign($data, $privkey_info, $algo);
		$seq = new Sequence(new DERData($data), $algo->toASN1(), 
			$signature->toBitString());
		return new PEM(PEM::TYPE_CERTIFICATE_REQUEST, $seq->toDER());
	}
}
