<?php

namespace X509\GeneralName;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
use X501\ASN1\Name;


/**
 * Implements <i>GeneralNames</i> ASN.1 type.
 *
 * Provides convenience methods to retrieve the first value of commonly used
 * CHOICE types.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class GeneralNames implements 
	\Countable, \IteratorAggregate
{
	/**
	 * GeneralName objects.
	 *
	 * @var GeneralName[] $_names
	 */
	protected $_names;
	
	/**
	 * Constructor
	 *
	 * @param GeneralName ...$names One or more GeneralName objects
	 */
	public function __construct(GeneralName ...$names) {
		$this->_names = $names;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		if (!count($seq)) {
			throw new \UnexpectedValueException(
				"GeneralNames must have at least one GeneralName.");
		}
		$names = array_map(
			function (UnspecifiedType $el) {
				return GeneralName::fromASN1($el->asTagged());
			}, $seq->elements());
		return new self(...$names);
	}
	
	/**
	 * Find first GeneralName by given tag.
	 *
	 * @param int $tag
	 * @return GeneralName|null
	 */
	protected function _findFirst($tag) {
		foreach ($this->_names as $name) {
			if ($name->tag() == $tag) {
				return $name;
			}
		}
		return null;
	}
	
	/**
	 * Check whether GeneralNames contains a GeneralName of given type.
	 *
	 * @param int $tag One of <code>GeneralName::TAG_*</code> enumerations
	 * @return bool
	 */
	public function has($tag) {
		return null !== $this->_findFirst($tag);
	}
	
	/**
	 * Get first GeneralName of given type.
	 *
	 * @param int $tag One of <code>GeneralName::TAG_*</code> enumerations
	 * @throws \OutOfBoundsException
	 * @return GeneralName
	 */
	public function firstOf($tag) {
		$name = $this->_findFirst($tag);
		if (!$name) {
			throw new \UnexpectedValueException("No GeneralName by tag $tag.");
		}
		return $name;
	}
	
	/**
	 * Get all GeneralName objects of given type.
	 *
	 * @param int $tag One of <code>GeneralName::TAG_*</code> enumerations
	 * @return GeneralName[]
	 */
	public function allOf($tag) {
		$names = array_filter($this->_names, 
			function (GeneralName $name) use ($tag) {
				return $name->tag() == $tag;
			});
		return array_values($names);
	}
	
	/**
	 * Get value of the first 'dNSName' type.
	 *
	 * @return string
	 */
	public function firstDNS() {
		$gn = $this->firstOf(GeneralName::TAG_DNS_NAME);
		if (!$gn instanceof DNSName) {
			throw new \RuntimeException(
				DNSName::class . " expected, got " . get_class($gn));
		}
		return $gn->name();
	}
	
	/**
	 * Get value of the first 'directoryName' type.
	 *
	 * @return Name
	 */
	public function firstDN() {
		$gn = $this->firstOf(GeneralName::TAG_DIRECTORY_NAME);
		if (!$gn instanceof DirectoryName) {
			throw new \RuntimeException(
				DirectoryName::class . " expected, got " . get_class($gn));
		}
		return $gn->dn();
	}
	
	/**
	 * Get value of the first 'uniformResourceIdentifier' type.
	 *
	 * @return string
	 */
	public function firstURI() {
		$gn = $this->firstOf(GeneralName::TAG_URI);
		if (!$gn instanceof UniformResourceIdentifier) {
			throw new \RuntimeException(
				UniformResourceIdentifier::class . " expected, got " .
					 get_class($gn));
		}
		return $gn->uri();
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		if (!count($this->_names)) {
			throw new \LogicException(
				"GeneralNames must have at least one GeneralName.");
		}
		$elements = array_map(
			function (GeneralName $name) {
				return $name->toASN1();
			}, $this->_names);
		return new Sequence(...$elements);
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_names);
	}
	
	/**
	 * Get iterator for GeneralName objects.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_names);
	}
}
