# Session Login End to End

This example builds a complete browser login flow with `SessionAuthStrategy` and Assegai Core 0.10.x. It covers application-owned user lookup, credential verification, protected routes, configurable login redirects, intended-target restoration, and logout.

## What owns each responsibility

- Your application loads users and chooses its login and logout routes.
- `SessionAuthStrategy` verifies the supplied credentials, rotates the session identifier, removes the password field from the stored user, and establishes session auth state.
- A Core guard decides whether a protected handler may run and raises `UnauthorizedException` when access is denied.
- Core's opt-in `LoginRedirectFilter` turns that exception into a browser redirect on controllers where the application applies it.
- Without that filter, the same guard failure keeps the normal `401 Unauthorized` response. No auth interceptor is required.

Install the packages on the 0.10 release line:

```bash
composer require assegaiphp/core:^0.10 assegaiphp/auth:^0.10
```

## Configure a Core-owned session

In an Assegai application, Core starts and closes the session around each request. Put non-secret auth policy and session-cookie settings in `config/auth.php`:

```php
<?php

return [
  'authentication' => [
    'loginRedirect' => [
      'url' => '/auth/login',
      'statusCode' => 302,
      'preserveTarget' => true,
      'targetSessionKey' => 'auth.intended_url',
      'excludedPaths' => [],
    ],
  ],
  'session' => [
    'name' => 'backoffice_session',
    'cookieLifetime' => 3600,
    'cookiePath' => '/',
    'cookieDomain' => '',
    'cookieSecure' => null,
    'cookieHttpOnly' => true,
    'cookieSameSite' => 'Lax',
  ],
];
```

`cookieSecure: null` lets Core enable secure cookies automatically for HTTPS. `SameSite=None` also forces secure cookies.

Do not pass `session_name` or `session_lifetime` to each strategy inside a Core application. Those options belong to the standalone mode described later; Core's already-active session is authoritative in a framework request.

## Load the user and verify credentials

The auth package does not prescribe a database layer. Your application repository loads the user, including its password hash, and hands it to the strategy:

```php
<?php

namespace App\Auth;

use App\Users\UsersRepository;
use Assegai\Auth\Strategies\SessionAuthStrategy;
use Assegai\Core\Attributes\Injectable;

#[Injectable]
final readonly class AuthService
{
  public function __construct(private UsersRepository $users)
  {
  }

  public function login(string $email, string $password): ?object
  {
    $user = $this->users->findByEmail($email);

    if (!$user) {
      return null;
    }

    $strategy = new SessionAuthStrategy([
      'user' => $user,
      'username_field' => 'email',
      'password_field' => 'password',
    ]);

    if (!$strategy->authenticate([
      'email' => $email,
      'password' => $password,
    ])) {
      return null;
    }

    return $strategy->getUser();
  }

  public function isAuthenticated(): bool
  {
    return (new SessionAuthStrategy())->isAuthenticated();
  }

  public function currentUser(): ?object
  {
    return (new SessionAuthStrategy())->getUser();
  }

  public function logout(): void
  {
    (new SessionAuthStrategy())->logout();
  }
}
```

`authenticate()` compares the configured username field, verifies the submitted password with `password_verify()`, and returns `false` for invalid credentials. Missing credential fields raise `MalformedCredentialsException`.

On success, the strategy calls `session_regenerate_id(true)`, stores the sanitized user at `$_SESSION['user']`, and returns that user from `getUser()`. The original application user object is not modified.

## Add the session guard

The guard only makes the access decision:

```php
<?php

namespace App\Auth;

use Assegai\Core\Attributes\Injectable;
use Assegai\Core\Interfaces\ICanActivate;
use Assegai\Core\Interfaces\IExecutionContext;

#[Injectable]
final readonly class SessionAuthGuard implements ICanActivate
{
  public function __construct(private AuthService $auth)
  {
  }

  public function canActivate(IExecutionContext $context): bool
  {
    return $this->auth->isAuthenticated();
  }
}
```

## Protect browser routes

Configure the guard failure and the browser response policy separately:

```php
<?php

namespace App\Dashboard;

use App\Auth\AuthService;
use App\Auth\SessionAuthGuard;
use Assegai\Core\Attributes\Controller;
use Assegai\Core\Attributes\Http\Get;
use Assegai\Core\Attributes\UseFilters;
use Assegai\Core\Attributes\UseGuards;
use Assegai\Core\Exceptions\Filters\LoginRedirectFilter;
use Assegai\Core\Exceptions\Http\UnauthorizedException;

#[Controller('dashboard')]
#[UseGuards(SessionAuthGuard::class, UnauthorizedException::class)]
#[UseFilters(LoginRedirectFilter::class)]
final readonly class DashboardController
{
  public function __construct(private AuthService $auth)
  {
  }

  #[Get]
  public function index(): array
  {
    return [
      'page' => 'dashboard',
      'user' => $this->auth->currentUser(),
    ];
  }
}
```

Core resolves `LoginRedirectFilter` through DI and reads `authentication.loginRedirect` from the active application's `config/auth.php`. The application therefore owns the login URL and every built-in redirect option.

The filter is terminal: once it handles `UnauthorizedException`, lower-precedence filters and the default exception handler do not emit another response. It runs before Core closes the request session, so the intended URL is persisted.

Only safe local `GET` and `HEAD` targets are stored. Cross-origin, scheme-relative, and malformed targets are rejected. The configured login path is automatically excluded, preventing redirect loops.

For a controller-specific policy, pass a configured `LoginRedirectFilter` instance to `UseFilters`. For behavior outside the built-in option surface, implement `ExceptionFilterInterface` and apply that custom filter instead.

Do not apply `LoginRedirectFilter` to API-only controllers. A guard that raises `UnauthorizedException` without this filter retains Core's normal 401 behavior.

## Add login and logout endpoints

```php
<?php

namespace App\Auth;

use Assegai\Core\Attributes\Controller;
use Assegai\Core\Attributes\Http\Body;
use Assegai\Core\Attributes\Http\Post;
use Assegai\Core\Attributes\Res;
use Assegai\Core\Exceptions\Http\BadRequestException;
use Assegai\Core\Exceptions\Http\UnauthorizedException;
use Assegai\Core\Http\Responses\Response;
use Assegai\Core\Session;
use stdClass;

#[Controller('auth')]
final readonly class AuthController
{
  public function __construct(
    private AuthService $auth,
    private Session $session,
  )
  {
  }

  #[Post('login')]
  public function login(#[Body] stdClass $body, #[Res] Response $response): Response
  {
    $email = $body->email ?? null;
    $password = $body->password ?? null;

    if (!is_string($email) || !is_string($password)) {
      throw new BadRequestException('Email and password are required.');
    }

    if (!$this->auth->login($email, $password)) {
      throw new UnauthorizedException('The supplied credentials are invalid.');
    }

    $target = $this->safeLocalTarget(
      $this->session->pull('auth.intended_url', '/dashboard'),
    );

    return $response->redirect($target, 303);
  }

  #[Post('logout')]
  public function logout(#[Res] Response $response): Response
  {
    $this->auth->logout();
    return $response->redirect('/auth/login', 303);
  }

  private function safeLocalTarget(mixed $target): string
  {
    if (
      !is_string($target) ||
      !str_starts_with($target, '/') ||
      str_starts_with($target, '//') ||
      preg_match('/[\r\n]/', $target)
    ) {
      return '/dashboard';
    }

    return $target;
  }
}
```

The 303 response changes the successful form POST into a GET. `Session::pull()` retrieves and removes the intended target so it is used only once. The additional local-target check protects the endpoint if some other application code writes an unsafe value to that session key.

Keep `GET /auth/login` public. `SessionAuthStrategy::logout()` clears session data, expires the session cookie, and destroys the active session before the application redirects.

Register `AuthService` and `SessionAuthGuard` as providers in the module that owns these controllers.

## Standalone PHP session configuration

Outside Core, the strategy owns session startup. Configure standalone session options on the strategy itself:

```php
<?php

use Assegai\Auth\Strategies\SessionAuthStrategy;

$strategy = new SessionAuthStrategy([
  'user' => $user,
  'username_field' => 'email',
  'password_field' => 'password',
  'session_name' => 'backoffice_session',
  'session_lifetime' => '+1 hour',
]);

if (!$strategy->authenticate([
  'email' => $_POST['email'] ?? '',
  'password' => $_POST['password'] ?? '',
])) {
  http_response_code(401);
  exit('Unauthorized');
}

header('Location: /dashboard', true, 303);
```

In standalone mode, `session_lifetime` accepts seconds or a relative date string understood by `strtotime()`. The strategy starts the session if necessary. Cookie path, domain, Secure, HttpOnly, and SameSite policy remain ordinary PHP session settings that the standalone application should configure before authentication.
