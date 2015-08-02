<?php

namespace noFlash\PkiAuthenticator;


class AuthenticationManager
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var AuthRequest
     */
    protected $request;

    /**
     * @var Service Fetched from request
     */
    protected $service;

    /**
     * @var AuthResponse
     */
    private $response;

    public function __construct(AuthRequest $request, Config $config = null)
    {
        $this->request = $request;
        $this->service = $request->getService();
        $this->config = Config::getInstance();
    }

    /**
     * @param Service $service
     *
     * @return AuthAdapterInterface
     */
    private function getAuthenticationAdapter()
    {
        //TODO add check for adapter interface

        $adapter = ($this->service->getAdapter()) ?: $this->config->getDefaultAdapter();
        if ($adapter === null) {
            throw new \RuntimeException('No suitable authentication adapter found');
        }

        if (class_exists($adapter)) { //Try FQCN
            return new $adapter;

        } elseif (class_exists('noFlash\PkiAuthenticator\Adapters\\' . $adapter . 'Adapter')) { //Try default adapter
            $class = 'noFlash\PkiAuthenticator\Adapters\\' . $adapter . 'Adapter';

            return new $class;
        }

        throw new \RuntimeException('Adapter specified for service cannot be initialized');
    }

    public function authenticate()
    {
        //TODO saving details to log with stacktrace id

        $adapter = $this->getAuthenticationAdapter();

        $this->response = $adapter->performAuthentication($this->request);
        if (!($this->response instanceof AuthResponse)) {
            throw new \RuntimeException('Invalid adapter response format');
        }

        if (!$this->response->isValid()) {
            throw new \RuntimeException('Adapter produced invalid response');
        }

        return $this->response->isAuthSucceed();
    }

    public function getRedirectUrl()
    {
        $b64Data = base64_encode($this->response->getEncryptedResponse());

        return sprintf($this->service->getRedirectUrl(), urlencode($b64Data));
    }

    public function getResponse()
    {
        if (empty($this->response)) {
            throw new \LogicException('Authentication has not been performed - you should call authenticate() first');
        }

        return $this->response;
    }
}
