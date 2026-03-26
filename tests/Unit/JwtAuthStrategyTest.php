<?php

use Assegai\Auth\Exceptions\AuthException;
use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Strategies\JwtAuthStrategy;

beforeEach(function (): void {
  unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['Authorization'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);

  $this->email = 'user@example.com';
  $this->password = 'password';
  $this->secret = 'replace-with-a-long-random-secret-key';
  $this->user = (object) [
    'id' => 7,
    'email' => $this->email,
    'password' => password_hash($this->password, PASSWORD_DEFAULT),
    'roles' => ['author'],
    'name' => 'Test User',
  ];
});

afterEach(function (): void {
  unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['Authorization'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
});

it('can be instantiated', function () {
  expect(new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]))->toBeInstanceOf(JwtAuthStrategy::class);
});

it('rejects short hmac secrets', function () {
  expect(fn () => new JwtAuthStrategy([
    'secret_key' => 'secret',
    'user' => $this->user,
  ]))->toThrow(AuthException::class);
});

it('can authenticate a user and issue a token', function () {
  $strategy = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);

  expect($strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]))->toBeTrue()
    ->and(explode('.', $strategy->getToken()))->toHaveCount(3);
});

it('can validate the issued token', function () {
  $strategy = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);
  $strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  expect($strategy->isAuthenticated())->toBeTrue();
});

it('throws for malformed credentials', function () {
  $strategy = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);

  expect(fn () => $strategy->authenticate(['email' => $this->email]))
    ->toThrow(MalformedCredentialsException::class);
});

it('can read bearer tokens from the authorization header', function () {
  $issuer = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);
  $issuer->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $issuer->getToken();

  $consumer = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);

  expect($consumer->isAuthenticated())->toBeTrue()
    ->and($consumer->getUser())->toHaveProperty('email', $this->email);
});

it('can issue a token for a trusted user directly', function () {
  $strategy = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);

  $token = $strategy->issueTokenForUser((object) [
    'id' => 11,
    'email' => 'oauth@example.com',
    'name' => 'OAuth User',
  ]);

  expect($token)->toBeString()->not->toBeEmpty()
    ->and($strategy->isAuthenticated())->toBeTrue()
    ->and($strategy->getUser())->toHaveProperty('email', 'oauth@example.com');
});

it('can logout a user and clear token state', function () {
  $strategy = new JwtAuthStrategy([
    'secret_key' => $this->secret,
    'user' => $this->user,
  ]);
  $strategy->authenticate([
    'email' => $this->email,
    'password' => $this->password,
  ]);

  $strategy->logout();

  expect($strategy->isAuthenticated())->toBeFalse()
    ->and($strategy->getToken())->toBe('');
});
