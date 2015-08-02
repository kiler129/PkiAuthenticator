<?php

namespace noFlash\PkiAuthenticator;


require_once('../src/Bootstrap.php');

if (!isset($_GET['data'], $_GET['svc'])) {
    throw new SecurityViolationException('Invalid auth call - consult documentation');
}

$data = base64_decode($_GET['data']); //AuthRequest expects raw binary data, to carry them inside url they need to be base64-encoded, so decode it first
if ($data === false) {
    throw new \InvalidArgumentException('Data decode failed');
}

$request = new AuthRequest($_GET['svc'], $data);
$authenticator = new AuthenticationManager($request);

if (!$authenticator->authenticate()) {
    throw new \LogicException('Authentication failed');
}

header('HTTP/1.0 307 Redirecting');
header('Location: ' . $authenticator->getRedirectUrl());
