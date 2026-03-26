# OAuth 2.0 Strategy Plan

This document turns the OAuth strategy idea into an implementation checklist for `assegaiphp/auth`.

The goal is:

- keep the package usable outside Assegai
- add OAuth 2.0 without forcing it into the existing username/password strategy shape
- let Assegai apps hand the OAuth result into either session auth or JWT auth

## What exists today

Current package surface:

- `AuthStrategyInterface`
- `SessionAuthStrategy`
- `JwtAuthStrategy`

Those strategies are useful for:

- validating known credentials
- issuing session-backed login state
- issuing JWT-backed login state

They are not a natural fit for OAuth redirects and callbacks.

## V1 scope

Implement OAuth 2.0 Authorization Code flow with PKCE.

V1 should include:

- generic provider support
- one first-party provider adapter
- session-backed state storage
- profile fetch + normalization
- handoff into existing session or JWT auth

V1 should not promise:

- OAuth 1.0
- full OpenID Connect validation
- refresh token rotation
- multiple polished provider adapters at launch
- automatic user persistence

## Phase 0: fix the current auth package first

These fixes should land before OAuth code is built on top.

### Session strategy fixes

File:

- `src/Strategies/SessionAuthStrategy.php`

Tasks:

- add one internal method for session bootstrap
- set session name and cookie params before `session_start()`
- make `isAuthenticated()`, `getUser()`, and `logout()` reuse that same bootstrap path
- make `logout()` clear `$_SESSION`
- expire the session cookie during logout

### JWT strategy fixes

File:

- `src/Strategies/JwtAuthStrategy.php`

Tasks:

- validate secret quality up front
- normalize bearer token parsing
- validate token lifetime safely
- make `logout()` clear both user and token state
- avoid relying only on `$_SERVER['HTTP_AUTHORIZATION']`

### Metadata cleanup

File:

- `composer.json`

Tasks:

- update the package description
- keep the package description aligned with what it actually provides

## Phase 1: add OAuth-specific abstractions

OAuth should not be forced into `AuthStrategyInterface`.

### New interfaces

Create:

- `src/Interfaces/OAuthProviderInterface.php`
- `src/Interfaces/OAuthStateStoreInterface.php`
- `src/Interfaces/OAuthUserResolverInterface.php`

Responsibilities:

- `OAuthProviderInterface`
  - build authorization URL
  - exchange authorization code for tokens
  - fetch remote user profile
- `OAuthStateStoreInterface`
  - persist `state`
  - persist PKCE verifier
  - validate and consume `state`
- `OAuthUserResolverInterface`
  - convert provider profile data into the local auth user shape the app wants

### Value objects

Create:

- `src/OAuth/ValueObjects/OAuthAuthorizationRequest.php`
- `src/OAuth/ValueObjects/OAuthTokenResponse.php`
- `src/OAuth/ValueObjects/OAuthUserProfile.php`
- `src/OAuth/ValueObjects/OAuthLoginResult.php`

Purpose:

- keep the flow typed and testable
- avoid passing around raw arrays everywhere

## Phase 2: add core OAuth services

### Config object

Create:

- `src/OAuth/OAuthProviderConfig.php`

Fields:

- `clientId`
- `clientSecret`
- `redirectUri`
- `authorizationEndpoint`
- `tokenEndpoint`
- `userInfoEndpoint`
- `scopes`
- optional provider-specific extras

### PKCE helper

Create:

- `src/OAuth/Support/Pkce.php`

Responsibilities:

- generate verifier
- generate challenge
- enforce valid method defaults

### State store

Create:

- `src/OAuth/State/SessionOAuthStateStore.php`

Responsibilities:

- write state and verifier into `$_SESSION`
- validate incoming callback state
- consume stored values so they cannot be reused

Note:

- this keeps the first version usable without Redis or database dependencies

### Flow coordinator

Create:

- `src/OAuth/OAuth2AuthStrategy.php`

This class should be the main public OAuth entry point.

Suggested responsibilities:

- `beginLogin()`
  - generate state
  - generate PKCE verifier/challenge
  - build provider authorization URL
- `handleCallback()`
  - validate callback state
  - exchange authorization code
  - fetch user profile
  - resolve local user shape
  - hand off into session or JWT strategy

Important:

- do not make this class depend on Assegai
- it should work in plain PHP projects too

## Phase 3: provider adapters

### Generic provider base

Create:

- `src/OAuth/Providers/AbstractOAuthProvider.php`

Responsibilities:

- shared HTTP calls
- standard OAuth request/response shaping
- reusable authorization URL builder

### First provider adapter

Pick one provider first and keep the implementation tight.

Suggested first adapter:

- GitHub

Create:

- `src/OAuth/Providers/GitHubOAuthProvider.php`

Why GitHub first:

- simple profile shape
- familiar for developer-tool sites
- good first real-world integration

## Phase 4: local auth handoff

OAuth alone only gives remote identity. The package still needs a clear way to hand that into local auth state.

### Session handoff

Reuse:

- `src/Strategies/SessionAuthStrategy.php`

Needed change:

- allow trusted local user objects to be established without re-validating password credentials
- this should be done through a dedicated method or helper, not by overloading `authenticate()`

Suggested addition:

- `establishAuthenticatedUser(object $user): void`

### JWT handoff

Reuse:

- `src/Strategies/JwtAuthStrategy.php`

Needed change:

- allow a trusted local user object to be converted into a token without password credentials

Suggested addition:

- `issueTokenForUser(object $user): string`

## Phase 5: Assegai bridge

Keep Assegai integration isolated from the standalone core OAuth logic.

Create:

- `src/Assegai/OAuthModule.php`
- `src/Assegai/Controllers/OAuthController.php`
- `src/Assegai/Services/OAuthService.php`

Responsibilities:

- expose routes like:
  - `/auth/{provider}/login`
  - `/auth/{provider}/callback`
- read provider config from app config
- delegate to `OAuth2AuthStrategy`

Important:

- the standalone OAuth classes should not depend on these Assegai files

## Phase 6: tests

### Session and JWT regression tests

Update:

- `tests/Unit/SessionAuthStrategyTest.php`
- `tests/Unit/JwtAuthStrategyTest.php`

Tasks:

- fix constant/session test setup issues
- add tests for the new trusted-user handoff methods

### OAuth unit tests

Add:

- `tests/Unit/OAuth2AuthStrategyTest.php`
- `tests/Unit/SessionOAuthStateStoreTest.php`
- `tests/Unit/PkceTest.php`
- `tests/Unit/GitHubOAuthProviderTest.php`

Test cases:

- builds authorization URL correctly
- stores and validates state
- rejects invalid state
- generates PKCE challenge correctly
- handles provider token exchange failure
- handles profile fetch failure
- returns a local login result
- can hand off to session auth
- can hand off to JWT auth

## Phase 7: docs

### Package README

Update:

- `README.md`

After code is real, document:

- standalone usage
- Assegai usage
- GitHub example
- session handoff
- JWT handoff
- the limits of v1

### Assegai docs and website

After the bridge exists, add:

- a getting started guide for OAuth login
- an advanced guide for provider config, PKCE, and local account mapping

Do not document auto-magic that does not exist yet.

## Suggested file checklist

### Existing files to modify

- `src/Strategies/SessionAuthStrategy.php`
- `src/Strategies/JwtAuthStrategy.php`
- `src/Interfaces/AuthStrategyInterface.php` only if absolutely necessary
- `composer.json`
- `README.md`
- `tests/Unit/SessionAuthStrategyTest.php`
- `tests/Unit/JwtAuthStrategyTest.php`

### New standalone OAuth files

- `src/Interfaces/OAuthProviderInterface.php`
- `src/Interfaces/OAuthStateStoreInterface.php`
- `src/Interfaces/OAuthUserResolverInterface.php`
- `src/OAuth/OAuth2AuthStrategy.php`
- `src/OAuth/OAuthProviderConfig.php`
- `src/OAuth/Support/Pkce.php`
- `src/OAuth/State/SessionOAuthStateStore.php`
- `src/OAuth/Providers/AbstractOAuthProvider.php`
- `src/OAuth/Providers/GitHubOAuthProvider.php`
- `src/OAuth/ValueObjects/OAuthAuthorizationRequest.php`
- `src/OAuth/ValueObjects/OAuthTokenResponse.php`
- `src/OAuth/ValueObjects/OAuthUserProfile.php`
- `src/OAuth/ValueObjects/OAuthLoginResult.php`

### Optional Assegai bridge files

- `src/Assegai/OAuthModule.php`
- `src/Assegai/Controllers/OAuthController.php`
- `src/Assegai/Services/OAuthService.php`

## Recommended implementation order

1. Fix session strategy and JWT strategy issues.
2. Add OAuth interfaces and value objects.
3. Add PKCE helper and session state store.
4. Implement `OAuth2AuthStrategy`.
5. Add one provider adapter.
6. Add trusted-user handoff into session and JWT strategies.
7. Add tests.
8. Add the Assegai bridge.
9. Update docs only after the runtime behavior exists.
