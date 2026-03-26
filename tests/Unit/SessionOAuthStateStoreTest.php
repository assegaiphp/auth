<?php

use Assegai\Auth\OAuth\State\SessionOAuthStateStore;

beforeEach(function (): void {
  if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    session_destroy();
  }

  $_SESSION = [];
});

afterEach(function (): void {
  if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    session_destroy();
  }

  $_SESSION = [];
});

it('stores and consumes state once', function () {
  $store = new SessionOAuthStateStore();
  $store->store('github', 'state-123', 'verifier-123');

  expect($store->consume('github', 'state-123'))->toBe('verifier-123')
    ->and($store->consume('github', 'state-123'))->toBeNull();
});

it('returns null for an invalid state', function () {
  $store = new SessionOAuthStateStore();
  $store->store('github', 'state-123', 'verifier-123');

  expect($store->consume('github', 'wrong-state'))->toBeNull();
});
