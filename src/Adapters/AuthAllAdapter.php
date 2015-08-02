<?php

namespace noFlash\PkiAuthenticator\Adapters;


use noFlash\PkiAuthenticator\AuthAdapterInterface;
use noFlash\PkiAuthenticator\AuthRequest;
use noFlash\PkiAuthenticator\AuthResponse;

class AuthAllAdapter implements AuthAdapterInterface
{

    /**
     * @param AuthRequest $request
     *
     * @return AuthResponse
     */
    function performAuthentication(AuthRequest $request)
    {
        return new AuthResponse(AuthResponse::AUTH_OK,
            ['uname' => $request->getUsername(), 'nonce' => $request->getNoonce()]);
    }
}
