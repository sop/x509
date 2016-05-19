<?php

namespace X509\CertificationPath\PathBuilding;

use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\Exception\PathBuildingException;


/**
 * Class for resolving certification paths.
 *
 * @link https://tools.ietf.org/html/rfc4158
 */
class CertificationPathBuilder
{
	/**
	 * Trust anchors.
	 *
	 * @var CertificateBundle
	 */
	protected $_trustList;
	
	/**
	 * Constructor
	 *
	 * @param CertificateBundle $trust_list List of trust anchors
	 */
	public function __construct(CertificateBundle $trust_list) {
		$this->_trustList = $trust_list;
	}
	
	/**
	 * Get all certification paths to given target certificate from
	 * any trust anchor.
	 *
	 * @param Certificate $target Target certificate
	 * @param CertificateBundle|null $intermediate Optional intermediate
	 *        certificates
	 * @return CertificationPath[]
	 */
	public function allPathsToTarget(Certificate $target, 
			CertificateBundle $intermediate = null) {
		$paths = $this->_resolvePathsToTarget($target, $intermediate);
		// map paths to CertificationPath objects
		return array_map(
			function ($certs) {
				return new CertificationPath(...$certs);
			}, $paths);
	}
	
	/**
	 * Resolve all possible certification paths from any trust anchor to
	 * the target certificate, using optional intermediate certificates.
	 *
	 * Helper method for allPathsToTarget to be called recursively.
	 *
	 * @todo Implement loop detection
	 * @param Certificate $target
	 * @param CertificateBundle $intermediate
	 * @return array[] Array of arrays containing path certificates
	 */
	private function _resolvePathsToTarget(Certificate $target, 
			CertificateBundle $intermediate = null) {
		// array of possible paths
		$paths = array();
		// signed by certificate in the trust list
		foreach ($this->_findIssuers($target, $this->_trustList) as $issuer) {
			// if target is self-signed, path consists of only
			// the target certificate
			if ($target->equals($issuer)) {
				$paths[] = array($target);
			} else {
				$paths[] = array($issuer, $target);
			}
		}
		if (isset($intermediate)) {
			// signed by intermediate certificate
			foreach ($this->_findIssuers($target, $intermediate) as $issuer) {
				// intermediate certificate must not be self-signed
				if ($issuer->isSelfIssued()) {
					continue;
				}
				// resolve paths to issuer
				$subpaths = $this->_resolvePathsToTarget($issuer, $intermediate);
				foreach ($subpaths as $path) {
					$paths[] = array_merge($path, array($target));
				}
			}
		}
		return $paths;
	}
	
	/**
	 * Get shortest path to given target certificate from any trust anchor.
	 *
	 * @param Certificate $target Target certificate
	 * @param CertificateBundle|null $intermediate Optional intermediate
	 *        certificates
	 * @throws PathBuildingException
	 * @return CertificationPath
	 */
	public function shortestPathToTarget(Certificate $target, 
			CertificateBundle $intermediate = null) {
		$paths = $this->allPathsToTarget($target, $intermediate);
		if (!count($paths)) {
			throw new PathBuildingException("No certification paths.");
		}
		usort($paths, 
			function ($a, $b) {
				return count($a) < count($b) ? -1 : 1;
			});
		return reset($paths);
	}
	
	/**
	 * Find all issuers of the target certificate from a given bundle.
	 *
	 * @param Certificate $target Target certificate
	 * @param CertificateBundle $bundle Certificates to search
	 * @return Certificate[]
	 */
	protected function _findIssuers(Certificate $target, 
			CertificateBundle $bundle) {
		$issuers = array();
		$issuer_name = $target->tbsCertificate()->issuer();
		$extensions = $target->tbsCertificate()->extensions();
		// find by authority key identifier
		if ($extensions->hasAuthorityKeyIdentifier()) {
			$ext = $extensions->authorityKeyIdentifier();
			if ($ext->hasKeyIdentifier()) {
				foreach ($bundle->allBySubjectKeyIdentifier(
					$ext->keyIdentifier()) as $issuer) {
					// check that issuer name matches
					if ($issuer->tbsCertificate()
						->subject()
						->equals($issuer_name)) {
						$issuers[] = $issuer;
					}
				}
			}
		}
		return $issuers;
	}
}
