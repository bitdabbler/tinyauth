# tinyauth (Tiny Token Auth)

## Overview

`tinyauth` is intended to provide a simple, **minimalist**, token-based authentication.

With token-based authentication, there is a fundamental tradeoff between how much we trust our users and how much load we put on our datastore. If we have high trust, we can reduce the load on our datastore by authenticating the user with state stored in a cryptographically secure session token. But, the longer the trust window is, the longer a session will remain valid even after we "inactivate" a user in our database. At the extreme where we have zero trust, we can check the datastore to re-verify the user on every request, making it similar to simply storing sessions in the datastore, in terms of how many times we call the datastore.

`tinyauth` allows you to manage this trade off using 3 levers:

- `MaxTrustsSecs` - the longest period between database checks
- `MaxStaleSecs` - the longest period a token can remain valid without being actively used
- `MaxTokenSecs` - the longest period a session can remain valid regardless of activity

`MaxTrustSecs` can be kept short, for high security without noticeably affecting users. The default is 10 minutes. At the end of `MaxTrustSecs`, `tinyauth` will check the datastore to ensure the user is still valid, then refresh the token transparently, all without bothering the user. That transparent refresh happens as long as (a) the user has been active within the last `MaxStaleSecs`, and (b) the last time the user logged in was within the last `MaxTokenSecs`.

If you use `tinyauth` middleware, it handles all of the token maintenance. The middleware, as well as the stock login and logout handlers, follow the standard library APIs for request handling. They will work directly with the standard library and all frameworks with compatible APIs, like Chi and Goji. 

If you want to write different middleware for other routing frameworks, it should be straightforward to integrate `tiny.Guard` as the auth state coordinator.

## Usage

To create a `tinyauth.Guard`, which will work as the auth state coordinator for your middleware, we need 3 things:

1. a pointer to any custom user type (e.g. `*Employee`), which only needs to implement the single method `Authable` interface:
    - `GetID()` - returns the user's unique identifier
2. a `*tinycrypto.Keyset`, to manage encryption transparently, including key rotation
3. a `tinyauth.Repo` implemention, used for state persistence:
    - `GetAuthable()` - fetch a user by ID
    - `BlacklistSession()` - register a sessionID in the blacklist table, to prevent auto-refreshing a dead session after logout
    - `CheckSessionBlacklist()` - check if a sessionID is in the blacklist

To create a `tinyauth.Guard`:

```go
guard := tinyauth.Guard(app.authKeyset, app.db, new(Employee))
router.Use(guard.Middleware)
```

## Limitations / Design Decisions

`tinyauth` does not use JWTs, or in this case, JWEs. We expose only the APIs required for our narrow design goals, keeping things secure but minimalist. We avoid the risk of using unsafe algorithms, and the overhead of unneeded default fields in JWT (and Paseto). There are many unsupported use cases, like those that need tokens the client can inspect but not modify (i.e. signed, but not encrypted). 

