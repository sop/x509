<?php

define("TEST_ASSETS_DIR", __DIR__ . "/assets");
require_once dirname(__DIR__) . "/vendor/autoload.php";

if (empty(ini_get("date.timezone"))) {
	ini_set("date.timezone", "UTC");
}
