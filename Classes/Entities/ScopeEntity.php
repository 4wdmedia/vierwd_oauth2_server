<?php

namespace Vierwd\VierwdOAuth2Server\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ScopeEntity implements ScopeEntityInterface {
    use EntityTrait;

    public function jsonSerialize() {
        return $this->getIdentifier();
    }
}