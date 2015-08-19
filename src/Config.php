<?php

namespace noFlash\PkiAuthenticator;


class Config
{
    const DEFAULT_SERVER_KEYCHAIN    = 'keys/';
    const DEFAULT_SERVER_PRIVATE_KEY = 'server_private.pem';

    /**
     * @var \noFlash\PkiAuthenticator\Config
     */
    private static $instance;

    /**
     * @var string|null
     */
    private $defaultAdapter;

    /**
     * @var array|null
     */
    private $defaultOptionsForAdapter;

    /**
     * @var Keychain
     */
    private $keychain;

    /**
     * @var array Array of services configuration
     */
    private $services;

    /**
     * @var string Private key used by server while encrypting tokens
     */
    private $serverPrivateKey;

    /**
     * @param null $file
     *
     * @return Config
     */
    public static function getInstance($file = null)
    {
        if (self::$instance === null) {
            if ($file === null) {
                throw new \LogicException('No Config instance was found - getInstance() should be called with file to build new instance');
            }

            self::$instance = new static($file);
        }

        return self::$instance;
    }

    private function __construct($source)
    {
        //TODO check config permissions!
        $configuration = json_decode(file_get_contents($source), true);
        if (!$configuration) {
            throw new \RuntimeException("Failed to parse configuration from file $source - " . json_last_error_msg());
        }

        if (isset($configuration['Server']['defaultAdapter'])) {
            $this->defaultAdapter = $configuration['Server']['defaultAdapter']; //Due to performance reasons it's not validated on config load
        }

        if (isset($configuration['Server']['defaultOptionsForAdapter'])) {
            $this->defaultOptionsForAdapter = $configuration['Server']['defaultOptionsForAdapter'];
        }

        $this->prepareKeychain($configuration);
        $this->loadServices($configuration);
    }

    private function prepareKeychain($configuration)
    {
        try {
            $keychainPath = (isset($configuration['Server']['keychain'])) ? $configuration['Server']['keychain'] : static::DEFAULT_SERVER_KEYCHAIN;
            $this->keychain = new Keychain($keychainPath, $this);

            $serverPrivateKey = (isset($configuration['Server']['privateKey'])) ? $configuration['Server']['privateKey'] : static::DEFAULT_SERVER_PRIVATE_KEY;
            if (!$this->keychain->verifyKey($serverPrivateKey)) {
                throw new \InvalidArgumentException("Failed to verify server private key at $serverPrivateKey");
            }

            $this->serverPrivateKey = $serverPrivateKey;

        } catch(\Exception $e) { //Keychain exceptions can contain sensitive information
            throw new \RuntimeException("Failed to initialize keychain", 0, $e);
        }
    }

    private function loadServices($configuration)
    {
        if (empty($configuration['Services'])) {
            throw new \LogicException('No services defined!');
        }

        $this->services = $configuration['Services'];
    }

    /**
     * @return Keychain
     */
    public function getKeychain()
    {
        return $this->keychain;
    }

    public function getService($name)
    {
        if (!isset($this->services[$name])) {
            throw new \InvalidArgumentException("There are no service named $name");
        }

        $service = new Service($name, $this);
        if (!isset($this->services[$name]['publicKey'])) {
            throw new \RuntimeException("Service $name configuration error - publicKey config value missing");
        }
        $service->setPublicKeyName($this->services[$name]['publicKey']);

        if (!isset($this->services[$name]['redirectUrl'])) {
            throw new \RuntimeException("Service $name configuration error - redirectUrl config value missing");
        }
        $service->setRedirectUrl($this->services[$name]['redirectUrl']);

        if (isset($this->services[$name]['adapter'])) {
            $service->setAdapter($this->services[$name]['adapter']);
        }

        if (isset($this->services[$name]['adapterOptions'])) {
            $service->setAdapterOptions((array)$this->services[$name]['adapterOptions']);
        }

        if (isset($this->services[$name]['useProvidedUser'])) {
            $service->setUseProvidedUser($this->services[$name]['useProvidedUser']);
        }

        return $service;
    }

    /**
     * @return string
     */
    public function getServerPrivateKey()
    {
        return $this->serverPrivateKey;
    }

    /**
     * @return null|string
     */
    public function getDefaultAdapter()
    {
        return $this->defaultAdapter;
    }

    /**
     * @return null|array
     */
    public function getDefaultOptionsForAdapter()
    {
        return $this->defaultOptionsForAdapter;
    }


}
