<?php

namespace noFlash\PkiAuthenticator;

class Keychain
{
    const TYPE_PRIVATE = 'private';
    const TYPE_PUBLIC  = 'public';

    /**
     * @var Config
     */
    private $config;

    /**
     * @var string Physical location of keychain on disk.
     */
    private $location;

    public function __construct($path, Config $config)
    {
        $this->config = $config;

        $this->location = realpath(APP_ROOT . DIRECTORY_SEPARATOR . $path);
        if (empty($this->location)) {
            $this->location = realpath($path); //Maybe path is absolute?

            if (empty($this->location)) {
                throw new \RuntimeException("Invalid keychain path - directory $path not found or insufficient permissions to access it");
            }
        }

        $this->verifyKeychainSecurity();
    }

    private function verifyKeychainSecurity()
    {
        //check chmods for folder & all keys
    }

    public function verifyKey($name)
    {
        $realKeyPath = realpath($this->location . DIRECTORY_SEPARATOR . $name . '.pem');
        if (empty($realKeyPath)) {
            throw new \InvalidArgumentException("Key $name not found in keychain (looked in " . $this->location . '/' . $name . '.pem)');
        }

        if (strpos($realKeyPath, $this->location) !== 0) {
            throw new SecurityViolationException("Jump outside keychain detected! Key from path $realKeyPath cannot be loaded.");
        }

        if (!is_readable($realKeyPath)) {
            throw new SecurityViolationException('Key file is inaccessible');
        }

        return true;
    }

    final private function getKey($name, $type)
    {
        if (!$this->verifyKey($name)) {
            return false;
        }

        $keyPath = 'file://' . realpath($this->location . DIRECTORY_SEPARATOR . $name . '.pem');

        if ($type === self::TYPE_PRIVATE) {
            $key = openssl_pkey_get_private($keyPath);

        } elseif ($type === self::TYPE_PUBLIC) {
            $key = openssl_pkey_get_public($keyPath);

        } else {
            throw new \InvalidArgumentException('Invalid key type specified');
        }

        if ($key === false) {
            throw new \RuntimeException('Failed to get key from PEM');
        }

        return $key;
    }

    /**
     * Performs decryption of data received from service.
     * Data need to be encrypted using service private key for this function to work (it uses service public key)
     *
     * @param Service $service
     * @param $data string Encrypted service data
     *
     * @return string Decrypted service data using it's public key
     */
    public function serviceDecrypt(Service $service, $encryptedData)
    {
        $key = $this->getKey($service->getPublicKeyName(), self::TYPE_PUBLIC);

        $decryptedData = '';
        if (!openssl_public_decrypt($encryptedData, $decryptedData, $key)) {
            throw new \RuntimeException('Service data decryption failed');
        }

        unset($key);
        gc_collect_cycles(); //Remove key from memory

        return $decryptedData;
    }

    public function serverEncrypt($plainData)
    {
        $key = $this->getKey($this->config->getServerPrivateKey(), self::TYPE_PRIVATE);

        $encryptedData = '';
        if (!openssl_private_encrypt($plainData, $encryptedData, $key)) {
            throw new \RuntimeException('Server data encryption failed');
        }

        unset($key);
        gc_collect_cycles(); //Remove key from memory

        return $encryptedData;
    }
}
