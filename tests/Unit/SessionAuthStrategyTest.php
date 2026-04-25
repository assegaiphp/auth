<?php

use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Strategies\SessionAuthStrategy;

beforeEach(function (): void {
  if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    session_destroy();
  }

  $_SESSION = [];
  $_COOKIE = [];

  $this->email = 'user@example.com';
  $this->password = 'password';
  $this->user = (object) [
    'id' => 7,
    'email' => $this->email,
    'password' => password_hash($this->password, PASSWORD_DEFAULT),
    'name' => 'Test User',
  ];
});

afterEach(function (): void {
  if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    session_destroy();
  }

  $_SESSION = [];
  $_COOKIE = [];
});

it('can be instantiated', function () {
  expect(new SessionAuthStrategy(['user' => $this->user]))
    ->toBeInstanceOf(SessionAuthStrategy::class);
});

it('can authenticate a user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  expect($strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]))->toBeTrue();
});

it('rotates the session identifier after credential authentication', function () {
  $knownSessionId = session_create_id('auth-');
  session_id($knownSessionId);

  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  expect($strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]))->toBeTrue()
    ->and(session_status())->toBe(PHP_SESSION_ACTIVE)
    ->and(session_id())->not->toBe($knownSessionId);
});

it('fails when the password is wrong', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  expect($strategy->authenticate([
    'email' => $this->email,
    'password' => 'wrongpassword',
  ]))->toBeFalse();
});

it('throws for malformed credentials', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  expect(fn () => $strategy->authenticate(['email' => $this->email]))
    ->toThrow(MalformedCredentialsException::class);
});

it('can report authentication state', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  expect($strategy->isAuthenticated())->toBeTrue();
});

it('can read the authenticated user without the password field', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  $authenticatedUser = $strategy->getUser();

  expect($authenticatedUser)
    ->toBeObject()
    ->toHaveProperty('email', $this->email)
    ->toHaveProperty('name', 'Test User')
    ->not->toHaveProperty('password');
});

it('can establish a trusted authenticated user directly', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $strategy->establishAuthenticatedUser((object) [
    'id' => 99,
    'email' => 'oauth@example.com',
    'name' => 'OAuth User',
  ]);

  expect($strategy->isAuthenticated())->toBeTrue()
    ->and($strategy->getUser())
    ->toHaveProperty('email', 'oauth@example.com');
});

it('rotates the session identifier when establishing a trusted user', function () {
  $knownSessionId = session_create_id('auth-');
  session_id($knownSessionId);

  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $strategy->establishAuthenticatedUser((object) [
    'id' => 99,
    'email' => 'oauth@example.com',
    'name' => 'OAuth User',
  ]);

  expect(session_status())->toBe(PHP_SESSION_ACTIVE)
    ->and(session_id())->not->toBe($knownSessionId);
});

it('can logout a user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  $strategy->logout();

  expect($strategy->isAuthenticated())->toBeFalse()
    ->and($strategy->getUser())->toBeNull();
});
