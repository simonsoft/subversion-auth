# subversion-auth

A `mod_lua` replacement for `mod_authz_svn` that authorizes Subversion-over-HTTP
requests against **role claims** (from an upstream authentication module,
e.g. `mod_auth_openidc`) instead of usernames, reading rules from an access
file that lives **inside** the repository itself.

## Installation

Tested on Debian (see `docker/Dockerfile` for the exact package set used in
CI/integration testing).

```sh
apt-get install apache2 libapache2-mod-svn subversion
a2enmod dav dav_svn lua
```

(`mod_lua` ships inside the `apache2`/`apache2-bin` package itself on
Debian -- there's no separate `libapache2-mod-lua` package to install.)

Deploy this repo's `mod-lua/` and `hooks/` directories to the server, e.g.
`/opt/subversion-auth/`. There's no build step -- the checkout itself is the
deployment layout.

## Apache httpd conf

```apache
<Location /svn>
    DAV svn
    SVNParentPath /var/svn/repos

    # Authentication: however your deployment validates the caller and
    # exposes their roles as a subprocess_env variable, e.g. mod_auth_openidc
    # populating OIDC_CLAIM_roles from a validated token claim. This module
    # does not perform authentication itself.

    LuaHookAuthChecker /opt/subversion-auth/mod-lua/svn-authz.lua authz_check_access

    # SetEnv AUTHZ_LUA_ACCS_DIR /var/lib/subversion-auth/accs   # default shown
    # SetEnv AUTHZ_LUA_ROLES_VAR AUTHZ_LUA_ROLES                # default shown; point this at
                                                                 # whatever variable your auth
                                                                 # module sets, e.g. OIDC_CLAIM_roles
    # SetEnv AUTHZ_LUA_LOCATION_PREFIX /svn                     # default shown; must match this
                                                                 # <Location> path
</Location>
```

`LuaHookAuthChecker` registers directly on Apache's `auth_checker` phase --
the same phase `mod_authz_svn` itself uses -- so it runs unconditionally once
configured, independent of any `Require` line, and mod_dav_svn's internal
per-child subrequests during directory listings, checkout/update REPORT
bodies, and log path redaction land here too (mod_dav_svn falls back to real
Apache subrequests through this same hook chain when no C-level authz bypass
provider is registered, which this module doesn't attempt to be). No
`LuaRoot` is needed since the directive above is given an absolute script
path directly.

Only Subversion's HTTPv2 wire protocol (1.7+) is supported. Requests using
the legacy DeltaV URI forms (`!svn/vcc`, `!svn/bln`, `!svn/wbl`, `!svn/bc`,
`!svn/act`, `!svn/wrk`) are refused outright. `!svn/ver/<rev>/<path>` is
*not* in that list despite Subversion's own HTTPv2 protocol notes naming it
as deprecated -- a real Apache 2.4.68 + Subversion 1.14.5 build still issues
it for the read-authorization subrequest that drives the root of a
checkout/update-report, so it's given the same treatment as `!svn/rvr`
instead (see the `LEGACY_STUBS` comment in `mod-lua/svn-authz.lua`).

## Access file format

Standard SVN authz ini syntax -- path sections granting `r`/`rw` to
`@role` entries -- but every role is a claim to match directly against the
caller's roles, not a resolved group of usernames. `[groups]`/`[aliases]`
sections are recognized (so the file stays syntactically standard) but
otherwise ignored; a group's membership is expected to be self-mapping, i.e.
just its own name:

```ini
[groups]
readers = readers
developers = developers

[/]
@readers = r
@developers = rw

[/trunk/vendor-drop]
@developers =
```

`@developers = rw` grants read+write to any caller whose role-claim list
(the comma-separated value of `AUTHZ_LUA_ROLES_VAR`) contains `developers`.
`@developers =` (no value) is an explicit deny, overriding an ancestor
section's grant for that role -- standard SVN authz syntax, distinct from
the role simply not being mentioned (which inherits from the nearest
ancestor section that does mention it). `*` always matches, for
world-readable/writable paths that don't require any specific claim.

Permissions granted to different roles at the same path combine (the most
permissive applies), and `COPY`/`MOVE` are checked **recursively**: every
access-file section nested under the source (for `COPY`'s read check) or
destination (write, for both `COPY` and `MOVE`) path must also grant the
required access, not just the top-level path -- otherwise copying a
directory could expose content from a nested path the caller can't actually
read. This is checked fresh at request time, not precomputed -- there's no
separate "copy" permission tier distinct from `r`/`rw`; a role that can
recursively copy a subtree is simply a role for which every section in that
subtree grants (at least) read.

`OPTIONS` and `MERGE` never require a role grant, only that the caller is
authenticated at all (enforced by Apache before this module ever runs) --
`OPTIONS` is capability negotiation and reveals no repository content;
`MERGE` finalizes a commit whose per-path writes were already checked as
they happened, on the preceding `!svn/txr/...` requests.

## In-repo access file

The access file is meant to live inside the repository itself (e.g.
`/access.accs`, versioned like any other file), not on the server's
filesystem -- but `svn-authz.lua` has no libsvn bindings, so it never reads
the repository directly. Instead, install `hooks/post-commit` as
`<repos>/hooks/post-commit`: it runs `svnlook` to export `/access.accs`'s
content to `AUTHZ_LUA_ACCS_DIR/<reponame>.accs` (atomically) whenever a
commit touches it, and that cache file is all `svn-authz.lua` ever reads.
A brand-new repository needs one manual bootstrap step first, though: with
no cache file yet, `svn-authz.lua` finds no rules and fails closed --
including for the commit that would add `/access.accs` in the first place.
Write an initial `AUTHZ_LUA_ACCS_DIR/<reponame>.accs` by hand (granting
whoever will run that first commit write access) before committing
anything; every commit after that, including the one that adds
`/access.accs` itself, keeps the cache file in sync automatically.

`AUTHZ_LUA_ACCS_DIR` and `AUTHZ_LUA_ACCESS_PATH` (the in-repo path,
default `/access.accs`) can both be overridden via environment variables
the hook script reads -- but note Apache's `SetEnv` is request-scoped and
does not reach hook subprocesses, so if you override these away from their
defaults, set them for the hook process itself too (e.g. in a wrapper),
not just via `SetEnv`.

## Running tests

### Unit tests (busted)

Fast, no Docker -- covers access-file parsing, permission resolution
(including inheritance and explicit denies), the recursive-descendant
check, method-to-access-type mapping, and HTTPv2 URI parsing (including
legacy-stub rejection), all against the real script with a mocked Apache
request object.

```sh
apt-get install lua5.3 liblua5.3-dev luarocks
luarocks --lua-version=5.3 install busted
busted spec/
```

### Integration tests (Docker)

The only way to validate that a real `mod_dav_svn` + `mod_lua` stack, and a
real `svn` client's actual HTTPv2 traffic, behave the way the unit tests
assume -- in particular, that recursive-copy authorization really denies a
copy when a nested path in the source subtree is unreadable. Requires
Docker.

```sh
./test/run-integration-tests.sh
```

Builds `docker/Dockerfile` (Debian + apache2 + subversion + mod_dav_svn +
mod_lua), starts it, creates a test repository, and drives the real `svn`
CLI and `curl` against it -- all from inside the container, so the host
needs nothing but Docker. `docker/test-roles.lua` is a **test-only** stand-in
for a real claims-issuing auth module (the `svn` CLI can only authenticate
via HTTP Basic, so the harness maps a couple of fixed test usernames to
role claims); it is not meant for production use.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
