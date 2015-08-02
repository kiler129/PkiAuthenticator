<?php

namespace noFlash\PkiAuthenticator;


interface SensitiveObjectInterface
{
    function purgeSensitiveInformation();
}
