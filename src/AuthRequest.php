<?php

namespace noFlash\PkiAuthenticator;


class AuthRequest implements SensitiveObjectInterface
{
    use SensitiveObjectClearer;

    /**
     * @var Service
     */
    private $service;

    /**
     * @var Config
     */
    private $config;

    /**
     * @var string
     */
    private $encryptedPayload;

    /**
     * @var string
     */
    private $decryptedPayload = [];

    /**
     * @param $serviceName
     * @param $requestPayload string Data encrypted using service private key (binary form!).
     */
    public function __construct($serviceName, $requestPayload)
    {
        $this->config = Config::getInstance();
        $this->service = $this->config->getService($serviceName);
        $this->encryptedPayload = $requestPayload;
        $this->decryptPayloadToCache();
    }

    private function decryptPayloadToCache()
    {
        $keychain = $this->config->getKeychain();
        $payload = $keychain->serviceDecrypt($this->service, $this->encryptedPayload);
        $payload = json_decode($payload, true);

        if (empty($payload)) {
            throw new \InvalidArgumentException('Failed to decode data after decryption - invalid format or empty value');
        }

        $this->decryptedPayload = $payload;
        if (!isset($this->decryptedPayload['nonce'])) {
            throw new \InvalidArgumentException('Malformed data - nonce missing');
        }

        if ($this->service->isUseProvidedUser() && !isset($this->decryptedPayload['uname'])) {
            throw new \InvalidArgumentException('Malformed data - uname missing while useProvidedUser is set');
        }
    }

    /**
     * @return Service
     */
    public function getService()
    {
        return $this->service;
    }

    public function getUsername()
    {
        if (empty($this->decryptedPayload)) {
            $this->decryptPayloadToCache();
        }

        return (isset($this->decryptedPayload['uname'])) ? $this->decryptedPayload['uname'] : null;
    }

    public function getNoonce()
    {
        if (empty($this->decryptedPayload)) {
            $this->decryptPayloadToCache();
        }

        return (isset($this->decryptedPayload['nonce'])) ? $this->decryptedPayload['nonce'] : null;
    }

    public function purgeSensitiveInformation()
    {
        $this->decryptedPayload = [];
    }
}
