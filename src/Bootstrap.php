<?php

namespace noFlash\PkiAuthenticator;

define('APP_ROOT', realpath(dirname(__FILE__) . DIRECTORY_SEPARATOR . '..'));
require_once(APP_ROOT . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php'); //Composer autoloader

//Initialize config
Config::getInstance(APP_ROOT . DIRECTORY_SEPARATOR . 'config.json');
