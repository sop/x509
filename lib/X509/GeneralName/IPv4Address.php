<?php

namespace X509\GeneralName;


class IPv4Address extends IPAddress
{
	/**
	 * Initialize from octets
	 *
	 * @param string $octets
	 * @throws \InvalidArgumentException
	 * @return self
	 */
	public static function fromOctets($octets) {
		$ip = null;
		$mask = null;
		$bytes = unpack("C*", $octets);
		switch (count($bytes)) {
		case 4:
			$ip = implode(".", $bytes);
			break;
		case 8:
			$ip = implode(".", array_slice($bytes, 0, 4));
			$mask = implode(".", array_slice($bytes, 4, 4));
			break;
		default:
			throw new \InvalidArgumentException("Invalid IPv4 octet length.");
		}
		return new self($ip, $mask);
	}
	
	protected function _octets() {
		$bytes = array_map("intval", explode(".", $this->_ip));
		if (isset($this->_mask)) {
			$bytes = array_merge($bytes, 
				array_map("intval", explode(".", $this->_mask)));
		}
		return pack("C*", ...$bytes);
	}
}
