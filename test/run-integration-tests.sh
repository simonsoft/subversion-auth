#!/usr/bin/env bash
# Builds the Docker image, starts it, and drives a real `svn` client and
# `curl` (both run *inside* the container via `docker exec`, so the host
# running this script needs nothing but Docker itself) against it to
# validate authorization end to end -- this is the only layer that can
# confirm the module's assumptions about Subversion's actual HTTPv2 wire
# traffic (see the plan's URI table) and that recursive-copy authorization
# really works against a real mod_dav_svn, not just the busted specs'
# simulation of it. Run from anywhere; paths below are resolved relative to
# this script.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="subversion-auth-test"
CONTAINER="subversion-auth-test-run"
PORT=8080

pass_count=0
fail_count=0

pass() { pass_count=$((pass_count + 1)); echo "  ok   - $1"; }
fail() { fail_count=$((fail_count + 1)); echo "  FAIL - $1"; }

cleanup() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        echo "==> Non-zero exit ($status); dumping Apache error log for debugging" >&2
        docker exec "$CONTAINER" tail -n 100 /var/log/apache2/error.log 2>&1 || true
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

dex() { docker exec "$CONTAINER" "$@"; }

svn_as() {
    local user="$1" pass="$2"
    shift 2
    dex svn --non-interactive --no-auth-cache --username "$user" --password "$pass" "$@"
}

status_as() {
    local user="$1" pass="$2" method="$3" url="$4"
    dex curl -s -o /dev/null -w '%{http_code}' -u "$user:$pass" -X "$method" "$url"
}

echo "==> Building image"
docker build -f "$ROOT/docker/Dockerfile" -t "$IMAGE" "$ROOT"

echo "==> Starting container"
docker run -d --name "$CONTAINER" -p "$PORT:80" "$IMAGE" >/dev/null

echo "==> Waiting for readiness (expect 401 on /svn/ once Apache is up)"
for _ in $(seq 1 30); do
    code="$(dex curl -s -o /dev/null -w '%{http_code}' http://localhost/svn/ || true)"
    [ "$code" = "401" ] && break
    sleep 1
done
if [ "$code" != "401" ]; then
    echo "Server never became ready (last status: ${code:-none})" >&2
    dex apache2ctl -t || true
    exit 1
fi

echo "==> Creating repository 'demo1' with the post-commit hook installed"
dex svnadmin create /var/svn/repos/demo1
dex cp /opt/subversion-auth/hooks/post-commit /var/svn/repos/demo1/hooks/post-commit
dex chmod +x /var/svn/repos/demo1/hooks/post-commit
dex chown -R www-data:www-data /var/svn/repos/demo1

echo "==> Bootstrapping the accs cache (a brand-new repo has no rules yet, so"
echo "    without this the very first commit -- the one that adds access.accs"
echo "    itself -- would be denied; see hooks/post-commit's header comment)"
dex sh -c 'cat > /var/lib/subversion-auth/accs/demo1.accs <<EOF
[/]
@developers = rw
EOF'

echo "==> Seeding initial content (access.accs, trunk/file.txt, trunk/locked/secret.txt)"
dex mkdir -p /tmp/seed/trunk/locked
dex mkdir -p /tmp/seed/wildcard-open/revoked
# wildcard-open and wildcard-open/revoked mention ONLY "*" -- never
# readeruser's own "readers" role, not even to deny it -- so whatever
# access readeruser gets in either of these two directories is
# unambiguously coming from "*" alone, isolating its real effect. (An
# earlier version of this fixture also explicitly revoked "readers" by
# name, which happened to produce the same pass/fail outcome either way
# and so didn't actually distinguish real mod_authz_svn's behavior from a
# plausible-but-wrong alternative -- real mod_authz_svn does not maintain
# independent per-role inheritance chains: the first path section (walking
# from the target up to root) that mentions ANY of the caller's roles,
# including "*", wins outright and blocks fallback for ALL of their roles,
# not just the one that matched.)
dex sh -c 'cat > /tmp/seed/access.accs <<EOF
[/]
@readers = r
@developers = rw
* = r

[/trunk/locked]
@developers =
@readers =
* =

[/wildcard-open]
* = r

[/wildcard-open/revoked]
* =
EOF'
dex sh -c 'echo "hello" > /tmp/seed/trunk/file.txt'
dex sh -c 'echo "secret" > /tmp/seed/trunk/locked/secret.txt'
dex sh -c 'echo "via wildcard" > /tmp/seed/wildcard-open/file.txt'
dex sh -c 'echo "not via wildcard" > /tmp/seed/wildcard-open/revoked/file.txt'
dex svn import -q --non-interactive --username devuser --password devpass \
    /tmp/seed http://localhost/svn/demo1 -m "seed"

echo "==> Verifying the post-commit hook exported the access file"
if dex test -f /var/lib/subversion-auth/accs/demo1.accs; then
    pass "post-commit hook exported demo1.accs"
else
    fail "post-commit hook did not export demo1.accs"
fi

echo "==> Read access"
code="$(status_as readeruser readpass GET http://localhost/svn/demo1/trunk/file.txt)"
[ "$code" = "200" ] && pass "readeruser can GET a readable file" || fail "readeruser GET expected 200, got $code"

echo "==> Query string on the request URI"
# Apache splits the query string out of r.uri before any module (including
# mod_lua) ever sees it -- r.uri is always just the decoded path -- but
# this is worth pinning down explicitly against a real server rather than
# just trusting that, especially for a URL shape (repo root + query
# string) real clients/tools genuinely send.
code="$(status_as readeruser readpass GET "http://localhost/svn/demo1/?rweb=e.mkdir")"
[ "$code" = "200" ] && pass "a query string on the repo root doesn't affect authorization" || fail "expected 200, got $code"
code="$(status_as readeruser readpass GET "http://localhost/svn/demo1/trunk/locked/secret.txt?rweb=e.mkdir")"
[ "$code" = "403" ] && pass "a query string doesn't bypass a denial either" || fail "expected 403, got $code"

echo "==> OPTIONS exemption (no role required, only authentication)"
code="$(status_as readeruser readpass GET http://localhost/svn/demo1/trunk/locked/secret.txt)"
[ "$code" = "403" ] && pass "readeruser GET of an unreadable path is denied (sanity check)" || fail "expected 403, got $code"
code="$(status_as readeruser readpass OPTIONS http://localhost/svn/demo1/trunk/locked/secret.txt)"
[ "$code" = "200" ] && pass "readeruser OPTIONS on that same unreadable path still succeeds" || fail "expected 200, got $code"

echo "==> '*' wildcard role, against a real server"
# /wildcard-open mentions ONLY "*" -- readeruser's own "readers" role isn't
# mentioned there at all, not even to deny it -- so any read they get is
# unambiguously coming from "* = r" alone.
code="$(status_as readeruser readpass GET http://localhost/svn/demo1/wildcard-open/file.txt)"
[ "$code" = "200" ] && pass "readeruser reads via '*' alone" || fail "expected 200, got $code"
# One level deeper, "*" is explicitly revoked ("* ="), again with no
# mention of "readers" at all. Real mod_authz_svn does not maintain
# independent per-role inheritance chains: this "*" entry alone is enough
# to win over root's grant and block fallback for every caller, including
# ones whose own specific role was never touched here.
code="$(status_as readeruser readpass GET http://localhost/svn/demo1/wildcard-open/revoked/file.txt)"
[ "$code" = "403" ] && pass "'* =' revokes that wildcard-only access one level down" || fail "expected 403, got $code"

echo "==> Write access (commit workflow, exercises !svn/me + !svn/txr)"
dex rm -rf /tmp/wc-dev /tmp/wc-reader
if svn_as devuser devpass checkout -q http://localhost/svn/demo1 /tmp/wc-dev \
    && dex sh -c 'echo changed >> /tmp/wc-dev/trunk/file.txt' \
    && svn_as devuser devpass commit -q -m "edit" /tmp/wc-dev/trunk/file.txt; then
    pass "devuser can commit a change to /trunk"
else
    fail "devuser commit to /trunk should have succeeded"
fi

if svn_as readeruser readpass checkout -q http://localhost/svn/demo1 /tmp/wc-reader \
    && dex sh -c 'echo changed >> /tmp/wc-reader/trunk/file.txt' \
    && svn_as readeruser readpass commit -q -m "edit" /tmp/wc-reader/trunk/file.txt 2>/dev/null; then
    fail "readeruser commit to /trunk should have been denied"
else
    pass "readeruser cannot commit a change to /trunk"
fi

echo "==> Recursive-read authorization for server-side COPY"
# A single file has nothing nested beneath it to fail a recursive check on,
# unlike /trunk itself (which contains /trunk/locked -- see below).
if svn_as devuser devpass copy -q -m "copy a readable file" \
    http://localhost/svn/demo1/trunk/file.txt http://localhost/svn/demo1/trunk/file-copy.txt 2>/dev/null; then
    pass "devuser can COPY a file with no nested deny beneath it"
else
    fail "devuser COPY of a fully-readable file should have succeeded"
fi

# This is the key case: /trunk is writable (and readable) for devuser at
# its root, but /trunk/locked explicitly denies devuser. A recursive read
# check across the whole source subtree must catch that and refuse the
# copy, even though a non-recursive check on /trunk alone would pass.
if svn_as devuser devpass copy -q -m "copy trunk" \
    http://localhost/svn/demo1/trunk http://localhost/svn/demo1/trunk-with-locked-copy 2>/dev/null; then
    fail "devuser COPY of /trunk should have been denied (nested /trunk/locked deny)"
else
    pass "devuser COPY of /trunk is denied due to the nested /trunk/locked deny"
fi

echo "==> Legacy DAV URI refusal"
code="$(status_as devuser devpass GET http://localhost/svn/demo1/\!svn/bc/1/trunk/file.txt)"
[ "$code" = "403" ] && pass "legacy !svn/bc URI is refused" || fail "legacy URI expected 403, got $code"

echo
echo "==> $pass_count passed, $fail_count failed"
[ "$fail_count" -eq 0 ]
