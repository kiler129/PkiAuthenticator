<?php

namespace noFlash\PkiAuthenticator\Adapters;


use noFlash\PkiAuthenticator\AuthAdapterInterface;
use noFlash\PkiAuthenticator\AuthRequest;
use noFlash\PkiAuthenticator\AuthResponse;

class FakeAuthAdapter implements AuthAdapterInterface
{
    /**
     * @var string|null
     */
    private $fakeUser;

    /**
     * @param AuthRequest $request
     *
     * @return AuthResponse
     */
    function performAuthentication(AuthRequest $request)
    {
        $responsePayload = ['nonce' => $request->getNoonce()];

        if ($request->getService()->isUseProvidedUser()) { //Service is configured to use username provided by itself
            if (empty($request->getUsername())) { //...but request lacks username
                return new AuthResponse(AuthResponse::NO_USER_PROVIDED, $responsePayload);

            } elseif ($this->fakeUser !== $request->getUsername()) { //...or username logged doesn't match one provided in request
                return new AuthResponse(AuthResponse::USER_MISSMATCH, $responsePayload);
            }
        }

        $responsePayload['uname'] = $this->fakeUser;

        return new AuthResponse(AuthResponse::AUTH_OK, $responsePayload);
    }

    /**
     * @param array $options
     *
     * @return void
     */
    function setOptions(array $options)
    {
        if (empty($options['user'])) {
            throw new \RuntimeException('FakeAuthAdapter require "user" option to be set');
        }

        $this->fakeUser = $options['user'];
    }
}
