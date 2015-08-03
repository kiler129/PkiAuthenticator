<?php

namespace noFlash\PkiAuthenticator;


class AuthResponse implements SensitiveObjectInterface
{
    use SensitiveObjectClearer;

    const GENERAL_FAILURE  = -999; //Some internal error (or error which cannot be specified due to security reasons)
    const ADAPTER_FAILURE = -5; //Adapter was unable to authenticate user
    const TIMEOUT          = -4;
    const NO_USER_PROVIDED = -3; //Similar to USER_MISSMATCH but used when no user was provided (but useProvidedUser was enabled)
    const USER_MISSMATCH   = -2; //Used when useProvidedUser enabled and user sent is different from user provided
    const NO_SUCH_USER     = -1;
    const CONFLICT         = 0; //Authentication cannot determine correct code. Generaly it means failure, but service can decide whatever to do based on payload.
    const AUTH_OK          = 1;

    /**
     * @var array
     */
    protected $decryptedPayload;

    /**
     * @var integer
     */
    protected $code = self::CONFLICT;

    public function __construct($code, array $payload = [])
    {
        if (!$this->verifyCode($code)) {
            throw new \InvalidArgumentException('Specified response code is invalid');
        }

        $this->code = $code;
        $this->decryptedPayload = $payload;
    }

    protected function verifyCode($code)
    {
        static $codes = [
            self::GENERAL_FAILURE,
            self::ADAPTER_FAILURE,
            self::TIMEOUT,
            self::NO_USER_PROVIDED,
            self::USER_MISSMATCH,
            self::NO_SUCH_USER,
            self::CONFLICT,
            self::AUTH_OK
        ];

        return isset($codes[$code]);
    }

    public function getStatusCode()
    {
        return $this->code;
    }

    public function isAuthSucceed()
    {
        return ($this->getStatusCode() >= 0);
    }

    final public function isValid()
    {
        return (!$this->isAuthSucceed() || isset($this->decryptedPayload['uname'], $this->decryptedPayload['nonce'])); //In future more checks may be added
    }

    public function purgeSensitiveInformation()
    {
        $this->decryptedPayload = null;
    }

    public function getEncryptedResponse()
    {
        $payload = $this->decryptedPayload;
        $payload['_srv_nonce'] = unpack("H*", openssl_random_pseudo_bytes(32))[1];
        $payload['_code'] = $this->code;
        $payload['_time'] = time();
        $payload = json_encode($payload);
        if (empty($payload)) {
            throw new \RuntimeException('Payload packing error');
        }

        return Config::getInstance()->getKeychain()->serverEncrypt($payload);
    }

}
