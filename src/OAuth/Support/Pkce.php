<?php

namespace Assegai\Auth\OAuth\Support;

use RuntimeException;

class Pkce
{
  public static function generateVerifier(int $length = 64): string
  {
    $length = max(43, min(128, $length));
    $bytes = random_bytes((int) ceil($length * 0.75));

    return substr(rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='), 0, $length);
  }

  public static function createS256Challenge(string $verifier): string
  {
    if ($verifier === '') {
      throw new RuntimeException('PKCE verifier cannot be empty.');
    }

    return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
  }
}
