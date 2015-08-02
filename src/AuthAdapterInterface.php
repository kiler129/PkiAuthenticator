<?php

namespace noFlash\PkiAuthenticator;


interface AuthAdapterInterface
{
    /**
     * @param AuthRequest $request
     *
     * @return AuthResponse
     */
    function performAuthentication(AuthRequest $request);
}
