<?php

namespace noFlash\PkiAuthenticator\Adapters;


use noFlash\PkiAuthenticator\AuthAdapterInterface;
use noFlash\PkiAuthenticator\AuthRequest;
use noFlash\PkiAuthenticator\AuthResponse;

class IisNtlmAdapter implements AuthAdapterInterface
{
    /**
     * {@inheritdoc}
     */
    function performAuthentication(AuthRequest $request)
    {
        $responsePayload = ['nonce' => $request->getNoonce()];

        if (!isset($_SERVER['LOGON_USER'])) { //No user was logged in
            return new AuthResponse(AuthResponse::ADAPTER_FAILURE, $responsePayload);
        }

        if ($request->getService()->isUseProvidedUser()) { //Service is configured to use username provided by itself
            if (empty($request->getUsername())) { //...but request lacks username
                return new AuthResponse(AuthResponse::NO_USER_PROVIDED, $responsePayload);

            } elseif ($_SERVER['LOGON_USER'] !== $request->getUsername()) { //...or username logged doesn't match one provided in request
                return new AuthResponse(AuthResponse::USER_MISSMATCH, $responsePayload);
            }
        }

        return new AuthResponse(AuthResponse::AUTH_OK);
    }
}
