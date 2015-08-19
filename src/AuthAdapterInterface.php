<?php

namespace noFlash\PkiAuthenticator;


interface AuthAdapterInterface
{

    /**
     * @param array $options
     *
     * @return void
     */
    function setOptions(array $options);

    /**
     * @param AuthRequest $request
     *
     * @return AuthResponse
     */
    function performAuthentication(AuthRequest $request);
}
