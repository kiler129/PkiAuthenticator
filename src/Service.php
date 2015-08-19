<?php

namespace noFlash\PkiAuthenticator;


class Service
{
    /**
     * @var string Service name
     */
    private $name;

    /**
     * @var string
     */
    private $publicKeyName;

    /**
     * @var string Redirect pattern for service.
     */
    private $redirectUrl;

    /**
     * @var bool Whatever to us service-provided username. If set to true service must send desired username, if false
     *     server will authenticate any user and it's up to service to determine whatever user should access service
     *     resources.
     */
    private $useProvidedUser = false;

    /**
     * @var string|null
     */
    private $adapter;

    /**
     * @var array|null
     */
    private $adapterOptions;

    public function __construct($name, Config $config = null)
    {
        $this->name = $name;
        $this->config = ($config) ?: Config::getInstance();
    }

    /**
     * Provides service name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    public function getPublicKeyName()
    {
        return $this->publicKeyName;
    }

    /**
     * @param string $publicKeyName
     *
     * @return $this
     */
    public function setPublicKeyName($publicKeyName)
    {
        if (!$this->config->getKeychain()->verifyKey($publicKeyName)) {
            throw new \InvalidArgumentException('Failed to verify key');
        }

        $this->publicKeyName = $publicKeyName;

        return $this;
    }

    /**
     * @return string
     */
    public function getRedirectUrl()
    {
        return $this->redirectUrl;
    }

    /**
     * @param string $redirectUrl
     *
     * @return Service
     */
    public function setRedirectUrl($redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;

        return $this;
    }

    /**
     * @return boolean
     */
    public function isUseProvidedUser()
    {
        return $this->useProvidedUser;
    }

    /**
     * @param boolean $useProvidedUser
     *
     * @return Service
     */
    public function setUseProvidedUser($useProvidedUser)
    {
        $this->useProvidedUser = $useProvidedUser;

        return $this;
    }

    /**
     * @return string|null Authentication adapter name. It could be builtin adapter name or full class path
     */
    public function getAdapter()
    {
        return $this->adapter;
    }

    public function setAdapter($adapter)
    {
        $this->adapter = $adapter;

        return $this;
    }

    /**
     * @return array|null
     */
    public function getAdapterOptions()
    {
        return $this->adapterOptions;
    }

    /**
     * @param array|null $adapterOptions
     */
    public function setAdapterOptions($adapterOptions)
    {
        $this->adapterOptions = $adapterOptions;
    }
}
