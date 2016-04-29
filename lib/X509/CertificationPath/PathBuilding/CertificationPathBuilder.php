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
		$paths = array();
		// signed by certificate in trust list
		foreach ($this->_findIssuers($target, $this->_trustList) as $issuer) {
			$paths[] = array($issuer, $target);
		}
		if (isset($intermediate)) {
			// signed by intermediate certificate
			foreach ($this->_findIssuers($target, $intermediate) as $issuer) {
				$subpaths = $this->allPathsToTarget($issuer, $intermediate);
				foreach ($subpaths as $path) {
					$paths[] = array_merge($path->certificates(), 
						array($target));
				}
			}
		}
		return array_map(
			function ($certs) {
				return new CertificationPath(...$certs);
			}, $paths);
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
		$tbs_cert = $target->tbsCertificate();
		$extensions = $tbs_cert->extensions();
		// find by authority key identifier
		if ($extensions->hasAuthorityKeyIdentifier()) {
			$ext = $extensions->authorityKeyIdentifier();
			if ($ext->hasKeyIdentifier()) {
				$issuers = array_merge($issuers, 
					$bundle->allBySubjectKeyIdentifier($ext->keyIdentifier()));
			}
		}
		return $issuers;
	}
}
