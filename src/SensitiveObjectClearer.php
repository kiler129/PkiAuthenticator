<?php

namespace noFlash\PkiAuthenticator;


trait SensitiveObjectClearer
{
    private function verifyObjectInterface()
    {
        if (!($this instanceof AuthAdapterInterface)) {
            throw new \RuntimeException('SensitiveObjectClearer was attached to ' . get_class($this) . ' object, however it does not implement \noFlash\PkiAuthenticator\AuthAdapterInterface');
        }
    }

    public function __debugInfo()
    {
        $this->verifyObjectInterface();
        $this->purgeSensitiveInformation();

        return $this;
    }

    public function __set_state()
    {
        $this->verifyObjectInterface();
        $this->purgeSensitiveInformation();

        return $this;
    }

    public function __sleep()
    {
        $this->verifyObjectInterface();
        $this->purgeSensitiveInformation();
    }

    public function __clone()
    {
        $this->verifyObjectInterface();
        $this->purgeSensitiveInformation();
    }
}
