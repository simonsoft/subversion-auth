-- Loads the mod_lua auth_checker hook directly (it is not a require-able
-- module, just a script defining a global authz_check_access function, plus
-- the helper functions it's built from -- all left as plain globals rather
-- than `local`, matching mod-lua/svn-index.lua's convention, precisely so
-- each piece is independently testable here).
local function spec_dir()
    local source = debug.getinfo(1, "S").source:match("^@(.*)$")
    return source:match("(.*/)") or "./"
end

local ROOT = spec_dir() .. "../"

-- Defines (among other things) the OK/HTTP_FORBIDDEN globals this spec
-- asserts against directly -- see svn-authz.lua's own comment on why these
-- are plain httpd.h-value globals rather than mod_lua's documented (but,
-- for this hook type, empirically empty) "apache2" module table.
dofile(ROOT .. "mod-lua/svn-authz.lua")

local function make_request(method, uri, subprocess_env, headers_in)
    local r = {
        method = method or "GET",
        uri = uri or "/svn/demo1/trunk/file.txt",
        subprocess_env = subprocess_env or {},
        headers_in = headers_in or {},
        logs = {},
    }
    r.debug = function(self, msg) table.insert(self.logs, msg) end
    return r
end

describe("url_decode", function()
    it("decodes percent-encoded bytes", function()
        assert.are.equal("a b", url_decode("a%20b"))
    end)

    it("leaves '+' untouched (path decoding, not form decoding)", function()
        assert.are.equal("a+b", url_decode("a+b"))
    end)
end)

describe("normalize_path", function()
    it("defaults nil/empty to root", function()
        assert.are.equal("/", normalize_path(nil))
        assert.are.equal("/", normalize_path(""))
    end)

    it("adds a leading slash and strips a trailing one", function()
        assert.are.equal("/trunk/foo", normalize_path("trunk/foo/"))
    end)

    it("percent-decodes the path", function()
        assert.are.equal("/a b", normalize_path("/a%20b"))
    end)
end)

describe("parse_svn_uri", function()
    it("returns nil when the URI isn't under the configured location", function()
        assert.is_nil(parse_svn_uri("/other/demo1/trunk", "/svn"))
    end)

    it("parses a plain public URI", function()
        local p = parse_svn_uri("/svn/demo1/trunk/file.txt", "/svn")
        assert.are.equal("demo1", p.repo)
        assert.are.equal("/trunk/file.txt", p.path)
    end)

    it("treats the repo root (no trailing path) as '/'", function()
        local p = parse_svn_uri("/svn/demo1", "/svn")
        assert.are.equal("demo1", p.repo)
        assert.are.equal("/", p.path)
    end)

    it("parses !svn/rvr/<rev>/<path> (revision-root reads, COPY source)", function()
        local p = parse_svn_uri("/svn/demo1/!svn/rvr/42/trunk/file.txt", "/svn")
        assert.are.equal("demo1", p.repo)
        assert.are.equal("/trunk/file.txt", p.path)
    end)

    it("parses !svn/txr/<txn>/<path> (in-transaction writes, COPY/MOVE dest)", function()
        local p = parse_svn_uri("/svn/demo1/!svn/txr/0-abc/trunk/file.txt", "/svn")
        assert.are.equal("demo1", p.repo)
        assert.are.equal("/trunk/file.txt", p.path)
    end)

    it("parses !svn/vtxr/<name>/<path> the same as txr", function()
        local p = parse_svn_uri("/svn/demo1/!svn/vtxr/my-commit/trunk/", "/svn")
        assert.are.equal("/trunk", p.path)
    end)

    it("parses !svn/ver/<rev>/<path> the same as rvr", function()
        -- Despite being named as deprecated in Subversion's HTTPv2 protocol
        -- notes, a real Apache 2.4.68 + Subversion 1.14.5 build still issues
        -- this for its internal checkout/update-report root-authorization
        -- subrequest -- confirmed via the Docker integration tests, which
        -- failed every checkout until this was accepted rather than refused.
        local p = parse_svn_uri("/svn/demo1/!svn/ver/1/trunk/file.txt", "/svn")
        assert.are.equal("/trunk/file.txt", p.path)
    end)

    for _, stub in ipairs({ "me", "rev", "txn", "vtxn" }) do
        it("treats !svn/" .. stub .. " as path-less (no path-specific check)", function()
            local p = parse_svn_uri("/svn/demo1/!svn/" .. stub .. "/whatever", "/svn")
            assert.are.equal("demo1", p.repo)
            assert.is_nil(p.path)
        end)
    end

    for _, stub in ipairs({ "vcc", "bln", "wbl", "bc", "act", "wrk" }) do
        it("refuses the legacy !svn/" .. stub .. " stub", function()
            local p = parse_svn_uri("/svn/demo1/!svn/" .. stub .. "/42/trunk", "/svn")
            assert.is_true(p.legacy)
        end)
    end

    it("refuses an unrecognized !svn stub rather than treating it as a plain path", function()
        local p = parse_svn_uri("/svn/demo1/!svn/mystery/foo", "/svn")
        assert.is_true(p.legacy)
    end)

    it("ignores the revision number -- authorization is always against current rules", function()
        -- There is no per-revision dimension to the rules at all (the accs
        -- cache file has no history), so the revision number in !svn/rvr and
        -- !svn/ver URIs must never affect the derived path -- confirmed
        -- against a reference config that achieves the same property
        -- deliberately (rewriting away the revision number before checking
        -- authorization), citing the same real risk: without this, an old
        -- cached/pinned revision number could be used to probe or bypass
        -- rules that only exist in the current access file.
        local old_rev = parse_svn_uri("/svn/demo1/!svn/rvr/1/trunk/file.txt", "/svn")
        local new_rev = parse_svn_uri("/svn/demo1/!svn/rvr/999999/trunk/file.txt", "/svn")
        assert.are.equal(old_rev.path, new_rev.path)

        local old_ver = parse_svn_uri("/svn/demo1/!svn/ver/1/trunk/file.txt", "/svn")
        local new_ver = parse_svn_uri("/svn/demo1/!svn/ver/999999/trunk/file.txt", "/svn")
        assert.are.equal(old_ver.path, new_ver.path)
    end)
end)

describe("strip_scheme_host", function()
    it("strips scheme and host from an absolute Destination URI", function()
        assert.are.equal("/svn/demo1/trunk/x", strip_scheme_host("https://host:8080/svn/demo1/trunk/x"))
    end)

    it("passes through an already-relative path", function()
        assert.are.equal("/svn/demo1/trunk/x", strip_scheme_host("/svn/demo1/trunk/x"))
    end)
end)

describe("path_is_ancestor / path_is_strict_descendant", function()
    it("treats root as an ancestor of everything", function()
        assert.is_true(path_is_ancestor("/", "/trunk/foo"))
    end)

    it("treats a path as its own ancestor but not its own strict descendant", function()
        assert.is_true(path_is_ancestor("/trunk", "/trunk"))
        assert.is_false(path_is_strict_descendant("/trunk", "/trunk"))
    end)

    it("does not treat a sibling prefix as an ancestor", function()
        assert.is_false(path_is_ancestor("/trunk", "/trunk-old/foo"))
    end)

    it("recognizes a nested path as a strict descendant", function()
        assert.is_true(path_is_strict_descendant("/trunk/sub", "/trunk"))
    end)
end)

describe("parse_access_file", function()
    it("parses path sections and role grants, ignoring [groups]/[aliases]", function()
        local rules = parse_access_file([[
[groups]
developers = developers

[/]
@readers = r

[/trunk]
@developers = rw
]])
        assert.are.equal(2, #rules)
        assert.are.equal("/", rules[1].path)
        assert.are.equal("r", rules[1].grants.readers)
        assert.are.equal("/trunk", rules[2].path)
        assert.are.equal("rw", rules[2].grants.developers)
    end)

    it("strips an optional 'reponame:' prefix from the section name", function()
        local rules = parse_access_file("[demo1:/trunk]\n@developers = rw\n")
        assert.are.equal("/trunk", rules[1].path)
    end)

    it("ignores comments and blank lines", function()
        local rules = parse_access_file("# comment\n\n[/]\n; also a comment\n@readers = r\n")
        assert.are.equal("r", rules[1].grants.readers)
    end)

    it("sorts sections shallowest-path-first", function()
        local rules = parse_access_file("[/trunk/deep]\n@x = r\n[/]\n@x = r\n[/trunk]\n@x = r\n")
        assert.are.same({ "/", "/trunk", "/trunk/deep" }, { rules[1].path, rules[2].path, rules[3].path })
    end)
end)

describe("parse_roles", function()
    it("always includes the '*' wildcard", function()
        local roles = parse_roles(nil)
        assert.is_true(roles["*"])
    end)

    it("splits a comma-separated claim value and trims whitespace", function()
        local roles = parse_roles("developers, readers ,qa")
        assert.is_true(roles.developers)
        assert.is_true(roles.readers)
        assert.is_true(roles.qa)
    end)
end)

describe("resolve_permission", function()
    local rules = parse_access_file([[
[/]
@readers = r
@developers = rw

[/trunk/locked]
@developers = r
]])

    it("uses the root grant when no deeper section mentions the role", function()
        assert.are.equal("rw", resolve_permission(rules, "/trunk/anything", "developers"))
    end)

    it("lets a deeper section override for the role it explicitly mentions", function()
        assert.are.equal("r", resolve_permission(rules, "/trunk/locked", "developers"))
    end)

    it("returns nil for a role never mentioned", function()
        assert.is_nil(resolve_permission(rules, "/trunk", "nobody"))
    end)
end)

describe("permission_meets", function()
    it("treats an unmentioned role (nil) as no access", function()
        assert.is_false(permission_meets(nil, false))
    end)

    it("treats an explicit empty value ('role =') as no access, not as read", function()
        -- Standard SVN authz syntax: "developers =" with no value means an
        -- explicit deny, distinct from the role simply not being mentioned,
        -- and must not be misread as an empty-but-truthy "read" grant.
        assert.is_false(permission_meets("", false))
        assert.is_false(permission_meets("", true))
    end)

    it("grants read for both 'r' and 'rw'", function()
        assert.is_true(permission_meets("r", false))
        assert.is_true(permission_meets("rw", false))
    end)

    it("grants write only for 'rw'", function()
        assert.is_false(permission_meets("r", true))
        assert.is_true(permission_meets("rw", true))
    end)
end)

describe("best_permission", function()
    it("combines multiple role memberships, taking the most permissive", function()
        local rules = parse_access_file("[/]\n@readers = r\n@developers = rw\n")
        local roles = parse_roles("readers,developers")
        assert.are.equal("rw", best_permission(rules, "/", roles))
    end)
end)

describe("check_access recursive descendant check", function()
    -- This is the case the plan calls out explicitly: a directory that's
    -- readable at its root but has a narrower-permission subdirectory must
    -- fail a recursive check (as required for COPY source / MOVE+DELETE /
    -- COPY-MOVE destination), even though the top-level path alone would
    -- pass a non-recursive check.
    local rules = parse_access_file([[
[/]
@developers = rw

[/trunk/secret]
@developers = r
]])
    local roles = parse_roles("developers")

    it("passes a non-recursive write check on the readable/writable root", function()
        assert.is_true(check_access(rules, "/trunk", roles, { write = true, recursive = false }))
    end)

    it("fails a recursive write check because a nested section only grants read", function()
        assert.is_false(check_access(rules, "/trunk", roles, { write = true, recursive = true }))
    end)

    it("passes a recursive read check, since every nested section still grants read", function()
        assert.is_true(check_access(rules, "/trunk", roles, { write = false, recursive = true }))
    end)

    it("denies outright when the role has no permission at all at the target", function()
        local nobody = parse_roles(nil)
        assert.is_false(check_access(rules, "/trunk", nobody, { write = false, recursive = false }))
    end)
end)

describe("access_needed_for_method", function()
    local function assert_needed(method, write, recursive)
        local needed = access_needed_for_method(method)
        assert.are.equal(write, needed.write)
        assert.are.equal(recursive, needed.recursive)
    end

    -- OPTIONS and MERGE are deliberately absent from every case below: in
    -- real dispatch, authz_check_access() never even calls this function
    -- for them (see EXEMPT_METHODS) -- they're always permitted once
    -- authenticated, with no role check at all. See the "authz_check_access"
    -- describe block for the test proving that exemption end to end.

    it("maps read methods to non-recursive read", function()
        assert_needed("GET", false, false)
        assert_needed("PROPFIND", false, false)
        assert_needed("REPORT", false, false)
    end)

    it("maps COPY to recursive read (its source-path check)", function()
        assert_needed("COPY", false, true)
    end)

    it("maps MOVE and DELETE to recursive write", function()
        assert_needed("MOVE", true, true)
        assert_needed("DELETE", true, true)
    end)

    it("maps other write methods to non-recursive write", function()
        assert_needed("MKCOL", true, false)
        assert_needed("PUT", true, false)
        assert_needed("PROPPATCH", true, false)
        assert_needed("CHECKOUT", true, false)
        assert_needed("MKACTIVITY", true, false)
        assert_needed("LOCK", true, false)
        assert_needed("UNLOCK", true, false)
    end)

    it("defaults an unrecognized method to recursive write", function()
        assert_needed("PATCH", true, true)
    end)
end)

describe("load_rules", function()
    it("returns no rules (fail closed) when the cache file doesn't exist", function()
        assert.are.same({}, load_rules("/nonexistent/dir", "demo1"))
    end)
end)

describe("authz_check_access", function()
    local accs_dir = spec_dir() .. "fixtures"

    -- developers gets read+write everywhere by default (granted at "/"),
    -- with no overrides beneath /branches -- used for the "everything
    -- succeeds" cases. /trunk/locked carves out an explicit deny
    -- ("@developers =", standard SVN authz syntax for "no access", not
    -- merely "unmentioned") for developers specifically, so any test
    -- against /trunk that also touches /trunk/locked exercises the
    -- recursive-descendant check in isolation from the destination-write
    -- check, which is exercised separately (readers never has write access
    -- anywhere in this fixture). /access.accs mirrors the real-world
    -- pattern that motivated this fixture shape: a reference OpenIDC-based
    -- config in production restricts write (and, there, also read) on the
    -- access file itself to admin-only roles, which is exactly the kind of
    -- nested override the recursive-descendant walk exists to catch.
    setup(function()
        os.execute("mkdir -p " .. accs_dir)
        local f = io.open(accs_dir .. "/demo1.accs", "w")
        f:write([[
[/]
@readers = r
@developers = rw

[/trunk/locked]
@developers =

[/access.accs]
@readers =
@developers = rw
]])
        f:close()
    end)

    teardown(function()
        os.remove(accs_dir .. "/demo1.accs")
    end)

    local function env(roles)
        return { AUTHZ_LUA_ACCS_DIR = accs_dir, AUTHZ_LUA_ROLES_VAR = "AUTHZ_LUA_ROLES", AUTHZ_LUA_ROLES = roles }
    end

    it("allows a read the caller's role grants", function()
        local r = make_request("GET", "/svn/demo1/trunk/file.txt", env("readers"))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("allows OPTIONS for an authenticated caller with no role grant at all", function()
        -- OPTIONS is exempt from role checks entirely (see EXEMPT_METHODS)
        -- -- capability negotiation reveals no repository content, and this
        -- module never sees a truly unauthenticated request anyway (Apache's
        -- own authentication phase runs first). env(nil) has no role claim
        -- whatsoever, so this only passes if OPTIONS is genuinely exempt,
        -- not merely coincidentally permitted by some role.
        local r = make_request("OPTIONS", "/svn/demo1/trunk/file.txt", env(nil))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("denies a write the caller's role doesn't grant", function()
        local r = make_request("PUT", "/svn/demo1/trunk/file.txt", env("readers"))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("allows a write the caller's role grants", function()
        local r = make_request("PUT", "/svn/demo1/trunk/file.txt", env("developers"))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("denies an explicit deny even though the parent path grants write", function()
        local r = make_request("PUT", "/svn/demo1/!svn/txr/0-a/trunk/locked/file.txt", env("developers"))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("allows COPY when both recursive source read and destination write succeed", function()
        local r = make_request(
            "COPY",
            "/svn/demo1/!svn/rvr/5/branches",
            env("developers"),
            { Destination = "/svn/demo1/!svn/txr/0-a/branches-copy" }
        )
        -- Neither /branches nor /branches-copy has any nested override, and
        -- both inherit developers=rw straight from the "/" section.
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("denies COPY whose recursive source read fails under a nested deny", function()
        local r = make_request(
            "COPY",
            "/svn/demo1/!svn/rvr/5/trunk",
            env("developers"),
            { Destination = "/svn/demo1/!svn/txr/0-a/trunk-copy" }
        )
        -- developers can read /trunk itself but /trunk/locked explicitly
        -- denies them, which must fail the recursive check even though a
        -- non-recursive check on /trunk alone would pass.
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("recursive read of the whole tree is denied for a role excluded only at /access.accs", function()
        -- The concrete real-world shape that started this review: a role
        -- (readers) has plain read at the root and everywhere else, but
        -- /access.accs -- an ordinary nested override, no different in kind
        -- from /trunk/locked above -- excludes it entirely. A non-recursive
        -- read anywhere else must be unaffected; only a recursive operation
        -- spanning the whole tree (like a COPY of the repository root) has
        -- to notice the exclusion and fail. Uses check_access() directly,
        -- not a full COPY request, specifically to isolate this from the
        -- unrelated fact that readers also has no write grant anywhere --
        -- see the destination-write-failure case above for that.
        local rules = load_rules(accs_dir, "demo1")
        local roles = parse_roles("readers")
        assert.is_true(check_access(rules, "/", roles, { write = false, recursive = false }))
        assert.is_false(check_access(rules, "/", roles, { write = false, recursive = true }))
    end)

    it("denies COPY whose destination write fails, even with readable source", function()
        local r = make_request(
            "COPY",
            "/svn/demo1/!svn/rvr/5/branches",
            env("readers"),
            { Destination = "/svn/demo1/!svn/txr/0-a/branches-copy" }
        )
        -- readers can recursively read /branches but has no write grant
        -- anywhere, so the destination check must fail.
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("denies COPY/MOVE with no Destination header", function()
        local r = make_request("COPY", "/svn/demo1/!svn/rvr/5/branches", env("developers"))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("denies a cross-repository COPY", function()
        local r = make_request(
            "COPY",
            "/svn/demo1/!svn/rvr/5/branches",
            env("developers"),
            { Destination = "/svn/other-repo/!svn/txr/0-a/branches-copy" }
        )
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("refuses a legacy DAV URI regardless of role", function()
        local r = make_request("GET", "/svn/demo1/!svn/bc/5/trunk/file.txt", env("developers"))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("allows requests outside the configured location untouched", function()
        local r = make_request("GET", "/other/path", env(nil))
        assert.are.equal(OK, authz_check_access(r))
    end)
end)

describe("authz_check_access with the '*' wildcard role", function()
    local accs_dir = spec_dir() .. "fixtures"

    -- "*" grants read to literally any caller at the root (no claim needed
    -- at all -- see env(nil) below), including one holding some unrelated
    -- real role, since parse_roles() always injects "*" into every caller's
    -- role set regardless of their actual claims. /private then revokes it
    -- with "* =" (empty value, an explicit deny, not merely "unmentioned")
    -- -- the same mechanism used to revoke any other role's inherited
    -- grant, just applied to the wildcard -- while admin keeps an explicit
    -- grant there that survives the wildcard's revocation.
    setup(function()
        os.execute("mkdir -p " .. accs_dir)
        local f = io.open(accs_dir .. "/wildcard-demo.accs", "w")
        f:write([[
[/]
* = r
@admin = rw

[/private]
* =
@admin = rw
]])
        f:close()
    end)

    teardown(function()
        os.remove(accs_dir .. "/wildcard-demo.accs")
    end)

    local function env(roles)
        return { AUTHZ_LUA_ACCS_DIR = accs_dir, AUTHZ_LUA_ROLES_VAR = "AUTHZ_LUA_ROLES", AUTHZ_LUA_ROLES = roles }
    end

    it("grants read at the root to a caller with no role claim at all", function()
        local r = make_request("GET", "/svn/wildcard-demo/file.txt", env(nil))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("grants read at the root to a caller holding some unrelated real role", function()
        -- Proves "*" matches regardless of which roles the caller actually
        -- has, not just the no-claim-at-all case above.
        local r = make_request("GET", "/svn/wildcard-demo/file.txt", env("somebody-else"))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("does not grant write at the root -- '*' was only ever given 'r'", function()
        local r = make_request("PUT", "/svn/wildcard-demo/file.txt", env(nil))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("'* =' revokes the wildcard's inherited grant at a nested path", function()
        local r = make_request("GET", "/svn/wildcard-demo/private/file.txt", env(nil))
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("an explicit role grant at that same nested path survives the wildcard revocation", function()
        local r = make_request("GET", "/svn/wildcard-demo/private/file.txt", env("admin"))
        assert.are.equal(OK, authz_check_access(r))
    end)

    it("recursive COPY of the root is denied for a wildcard-only caller because of the nested revocation", function()
        -- Mirrors the /access.accs recursive-descendant case above, but for
        -- the wildcard specifically: a non-recursive read of the root
        -- succeeds via "*", yet copying the whole tree must notice that
        -- /private revoked "*" and fail, even though the caller never held
        -- any role beyond the wildcard to begin with.
        local r = make_request(
            "COPY",
            "/svn/wildcard-demo/!svn/rvr/5/",
            env(nil),
            { Destination = "/svn/wildcard-demo/!svn/txr/0-a/whole-tree-copy" }
        )
        assert.are.equal(HTTP_FORBIDDEN, authz_check_access(r))
    end)

    it("recursive COPY of the root succeeds for admin, who has an explicit grant throughout", function()
        local r = make_request(
            "COPY",
            "/svn/wildcard-demo/!svn/rvr/5/",
            env("admin"),
            { Destination = "/svn/wildcard-demo/!svn/txr/0-a/whole-tree-copy" }
        )
        assert.are.equal(OK, authz_check_access(r))
    end)
end)
