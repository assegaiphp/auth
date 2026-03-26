<?php

use Assegai\Auth\OAuth\Support\Pkce;

it('generates a verifier in the valid pkce length range', function () {
  $verifier = Pkce::generateVerifier();

  expect(strlen($verifier))->toBeGreaterThanOrEqual(43)
    ->toBeLessThanOrEqual(128);
});

it('creates a stable s256 challenge', function () {
  $challenge = Pkce::createS256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

  expect($challenge)->toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});
