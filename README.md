# tinyauth (Tiny Token Auth)

## Overview

`tinyauth` is intended to provide a simple, **minimalist**, token-based authentication.

WIth token-based authentication, there is a fundamental tradeoff we have to make. If we have high trust, then we can reduce the load on the database by authenticating the user with just the state in the cryptographically secure session token. But, the longer the trust window is, the longer a session will remain valid even after we "inactivate" a user in our database. If we have zero trust, then we can check the DB to see if the user is still valid on every single request (effectively equivalent to simply storing sessions in the DB).

`tinyauth` allows you to manage this trade off using 3 levers. `MaxTrustsSecs` determines the longest amount of time (in seconds) between database checks. `MaxStaleSecs` determines the longest period that a token can remain valid without it being actively used. Finally, `MaxTokenSecs` determines the longest possible time a session can remain active before a user must login again. If you use `tinyauth` middleware, it handles all of the token maintenance.

Note, `MaxTrustSecs` can be kept quite short (the default is 10 minutes), without annoying users too much. As long as the token is not stale and the session is not too old, the token will refresh itself transparently after checking the database, without bothering the user.

The middleware (and stock login/logout handlers) follow the standard library APIs for request handling, so they will work directly with the standard library, as well as compatible frameworks like Chi and Goji. It should generally be straightforward if you want to use the `Guard` as your auth state coordinator and write different middleware for other routing frameworks.

Finally, `tinyauth` doesn't use JWTs, or in this case, JWEs, because we want to expose only the APIs required for our narrow design goals (secure, and minimalist). We avoid the risk of using unsafe algorithms, and we throw out unnecessary default fields in JWT (and Paseto). `tinyauth` really is intentionally minimalist. We understand that there are many unsupported use cases, like those that require tokens that client can see (but not modify) because they are signed, but not encrypted. 


## Usage

To create a guard, which will work as the auth state manager for your middleware, you'll need 3 things:

1. a pointer to any custom "user" type (e.g. `*Employee`), which only needs to implement the one function in the `Authable` interface:
    - `GetID()` - returns the user's unique identifier
2. a `*tinycrypto.Keyset`, to manage encryption transparently
3. a `tinyauth.Repo`, which is used for state persistence; it includes
    - `GetAuthable()` - fetch a user by ID
    - `BlacklistSession()` - register a sessionID in the blacklist table, to prevent auto-refreshing a dead session after logout
    - `CheckSessionBlacklist()` - check if a sessionID is in the blacklist

```go
guard := tinyauth.Guard(app.authKeyset, app.db, new(Employee))
router.Use(guard.Middleware)
```
