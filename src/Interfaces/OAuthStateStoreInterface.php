<?php

namespace Assegai\Auth\Interfaces;

interface OAuthStateStoreInterface
{
  public function store(string $provider, string $state, ?string $codeVerifier = null): void;

  public function consume(string $provider, string $state): ?string;
}
