-- Apache mod_lua replacement for mod_authz_svn, wired in via LuaHookAuthChecker
-- (the same ap_hook_auth_checker phase mod_authz_svn itself registers on, so
-- it runs unconditionally once configured -- no `Require` line needed -- and
-- mod_dav_svn's internal per-child subrequests during directory listings,
-- checkout/update REPORT bodies, and log redaction land here too, since
-- mod_dav_svn falls back to real Apache subrequests through this same hook
-- chain whenever the fast C-level authz-provider bypass isn't registered).
--
-- Unlike mod_authz_svn, permissions are granted per *role claim* rather than
-- per username: the access file's [groups] entries are expected to be
-- self-mapping (e.g. "developers = developers"), and a role grants access
-- when its name appears in the caller's role-claim list. The access file
-- itself is not read from the repository directly (no libsvn bindings are
-- available from Lua) -- it is expected to have been exported by the
-- `hooks/post-commit` script into AUTHZ_LUA_ACCS_DIR as "<repo>.accs".
--
-- Only Subversion's HTTPv2 wire protocol is supported (see
-- notes/http-and-webdav/http-protocol-v2.txt in the Subversion source).
-- Requests using the legacy DeltaV URI stubs (!svn/vcc, !svn/bln, !svn/wbl,
-- !svn/bc, !svn/act, !svn/wrk) are refused outright -- see the LEGACY_STUBS
-- comment below for why !svn/ver is deliberately not in that list despite
-- being named as deprecated in the HTTPv2 protocol notes.

-- mod_lua's documented "apache2" module (constants like OK,
-- HTTP_FORBIDDEN) turns out, empirically, to only be populated for
-- LuaAuthzProvider-registered provider callbacks -- for a LuaHookAuthChecker
-- hook (what this module uses), `require "apache2"` returns an empty table
-- and those fields are nil, confirmed by inspecting it directly against a
-- real Apache/mod_lua build (Debian trixie, httpd 2.4.68). These are
-- Apache's own well-known httpd.h values instead.
OK = 0
HTTP_FORBIDDEN = 403

-- Confirmed against a real Apache 2.4.68 + Subversion 1.14.5 build: despite
-- notes/http-and-webdav/http-protocol-v2.txt listing "!svn/ver" among the
-- resources HTTPv2 eliminates, mod_dav_svn still issues it for at least one
-- internal check (the read-authorization subrequest driving the root of a
-- checkout/update-report's edit operation) even with an otherwise fully
-- HTTPv2 client -- refusing it as "legacy" broke every checkout. It's kept
-- out of this set and given the same read/rev+path treatment as !svn/rvr
-- below. The other DeltaV-era stubs did not appear anywhere in a full
-- checkout+commit+copy+move exercise against that same build.
local LEGACY_STUBS = {
    vcc = true, bln = true, wbl = true, bc = true, act = true, wrk = true,
}

-- Percent-decodes a URI path component. Unlike form decoding, "+" is left
-- alone here -- it has no special meaning in a URI path, only in an
-- application/x-www-form-urlencoded body/query string.
function url_decode(s)
    return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

function normalize_path(p)
    if p == nil or p == "" then
        return "/"
    end
    p = url_decode(p)
    if p:sub(1, 1) ~= "/" then
        p = "/" .. p
    end
    if #p > 1 and p:sub(-1) == "/" then
        p = p:sub(1, -2)
    end
    return p
end

-- Splits "/segment/rest..." into "segment", "/rest..." (rest is "" if none).
function split_first_segment(s)
    local seg, rest = s:match("^/?([^/]+)(.*)$")
    return seg, rest or ""
end

-- Parses a request URI (already stripped of scheme/host) into
-- { repo = <name>, path = <repos-relative path> or nil, legacy = true }.
-- `path` is nil for repo/transaction-level operations (!svn/me, !svn/rev/<r>,
-- !svn/txn|vtxn/<name>) where no path-specific check applies -- write
-- enforcement for those happens on the subsequent !svn/txr/<txn>/<path>
-- requests instead. Returns nil if `uri` isn't under `location_prefix`.
function parse_svn_uri(uri, location_prefix)
    if uri:sub(1, #location_prefix) ~= location_prefix then
        return nil
    end
    local rest = uri:sub(#location_prefix + 1)
    local repo, after_repo = split_first_segment(rest)
    if repo == nil then
        return nil
    end

    local stub = after_repo:match("^/!svn/([^/]+)")
    if stub == nil then
        return { repo = repo, path = normalize_path(after_repo) }
    end
    if LEGACY_STUBS[stub] then
        return { repo = repo, legacy = true }
    end
    if stub == "me" or stub == "rev" or stub == "txn" or stub == "vtxn" then
        return { repo = repo, path = nil }
    end
    if stub == "rvr" or stub == "txr" or stub == "vtxr" or stub == "ver" then
        -- /!svn/<stub>/<rev-or-txn>/<path...>
        local tail = after_repo:match("^/!svn/[^/]+/[^/]+(.*)$")
        return { repo = repo, path = normalize_path(tail) }
    end
    -- Unknown stub: refuse rather than silently treat as a plain path.
    return { repo = repo, legacy = true }
end

-- Strips "scheme://host[:port]" from a Destination header value, if present.
function strip_scheme_host(dest)
    return dest:match("^https?://[^/]+(/.*)$") or dest
end

function path_is_ancestor(ancestor, path)
    if ancestor == "/" then
        return true
    end
    if path == ancestor then
        return true
    end
    return path:sub(1, #ancestor + 1) == ancestor .. "/"
end

function path_is_strict_descendant(child, parent)
    if child == parent then
        return false
    end
    return path_is_ancestor(parent, child)
end

-- Parses an .accs file's content into a list of
-- { path = <normalized path>, grants = { [role] = "r"|"rw" } },
-- sorted shallowest-path-first so callers can apply parent-then-child
-- inheritance by walking the list in order. [groups] / [aliases] sections
-- are recognized (so the file stays syntactically standard) and ignored --
-- role matching is purely against the path-rule keys.
function parse_access_file(content)
    local sections = {}
    local current = nil
    for line in (content .. "\n"):gmatch("([^\n]*)\n") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" and trimmed:sub(1, 1) ~= ";" then
            local section_name = trimmed:match("^%[(.-)%]$")
            if section_name then
                if section_name == "groups" or section_name == "aliases" then
                    current = nil
                else
                    local path = section_name:match(":(.*)$") or section_name
                    current = { path = normalize_path(path), grants = {} }
                    table.insert(sections, current)
                end
            elseif current ~= nil then
                local key, val = trimmed:match("^([^=]-)%s*=%s*(.*)$")
                if key then
                    local role = key:match("^@?(.*)$")
                    current.grants[role] = val
                end
            end
        end
    end
    table.sort(sections, function(a, b) return #a.path < #b.path end)
    return sections
end

-- Builds the set of role claims to check, from a comma-separated claim
-- value. "*" (matching an unconditional access-file entry, e.g. "* = r")
-- is always included, mirroring the standard SVN authz "anyone" wildcard.
function parse_roles(claim_value)
    local roles = { ["*"] = true }
    if claim_value then
        for role in claim_value:gmatch("[^,]+") do
            local trimmed = role:match("^%s*(.-)%s*$")
            if trimmed ~= "" then
                roles[trimmed] = true
            end
        end
    end
    return roles
end

-- Resolves the effective permission ("r", "rw", "" for an explicit deny, or
-- nil for no access at all) for a caller holding `roles` at `path`.
--
-- This is NOT independent per-role inheritance -- that was this module's
-- original (wrong) model, disproven by testing against a real
-- mod_authz_svn: with "harry = rw" at "/" and only "* =" at "/locked"
-- (harry not mentioned there at all), a request from harry to "/locked"
-- is DENIED, even though his own root grant is never touched by name.
--
-- The real algorithm, confirmed against libsvn_repos/authz.c's actual
-- matching code and that live test: walk from `path` up toward the root,
-- through each explicitly configured section (deepest first -- `rules` is
-- sorted shallow-to-deep by parse_access_file, so this walks it in
-- reverse). At the FIRST section that mentions ANY role in `roles` --
-- including "*", and including as an explicit empty/deny entry -- that
-- section wins outright: combine (most permissive wins) just the roles
-- that are mentioned THERE, and stop. Shallower sections are never
-- consulted again, even for roles the winning section didn't mention.
--
-- The practical consequence: a role's grant at an ancestor path can be
-- silently shadowed by a DIFFERENT role (or "*") merely being mentioned --
-- for any reason, including to deny it -- at a more specific path, even
-- when the first role is never individually named there. That's exactly
-- what makes "* =" work as a revocation: "*" matches every caller, so its
-- mere presence at a path is enough to win and block fallback for
-- everyone, regardless of what any of their other roles would otherwise
-- have been granted higher up.
function best_permission(rules, path, roles)
    for i = #rules, 1, -1 do
        local section = rules[i]
        if path_is_ancestor(section.path, path) then
            local matched = false
            local best = nil
            for role, _ in pairs(roles) do
                local val = section.grants[role]
                if val ~= nil then
                    matched = true
                    if val == "rw" then
                        best = "rw"
                    elseif val == "r" and best ~= "rw" then
                        best = "r"
                    end
                end
            end
            if matched then
                return best
            end
        end
    end
    return nil
end

-- perm is nil when no matching section ever mentioned the role, or "" when
-- a section explicitly mentioned it with no value (e.g. "developers ="),
-- which is standard SVN authz syntax for an explicit deny -- both mean no
-- access, but "" additionally overrides any weaker inherited grant from an
-- ancestor section, which resolve_permission() already handles by treating
-- an explicit "" the same as any other explicit value.
function permission_meets(perm, need_write)
    if perm == nil or perm == "" then
        return false
    end
    if need_write then
        return perm == "rw"
    end
    return perm == "r" or perm == "rw"
end

-- The core access decision. `opts.recursive` implements what mod_authz_svn
-- calls svn_authz_recursive: rather than walking the actual repository
-- tree (which this module has no access to), it walks every *configured*
-- access-file section nested under `path` and requires each of them to
-- also grant the requested access -- sufficient because permissions only
-- change at explicitly configured path sections; everything in between
-- inherits unchanged from its nearest ancestor section.
function check_access(rules, path, roles, opts)
    if not permission_meets(best_permission(rules, path, roles), opts.write) then
        return false
    end
    if opts.recursive then
        for _, section in ipairs(rules) do
            if path_is_strict_descendant(section.path, path) then
                if not permission_meets(best_permission(rules, section.path, roles), opts.write) then
                    return false
                end
            end
        end
    end
    return true
end

local READ_METHODS = { GET = true, PROPFIND = true, REPORT = true }
local WRITE_METHODS = {
    MKCOL = true, PUT = true, PROPPATCH = true, CHECKOUT = true,
    MKACTIVITY = true, LOCK = true, UNLOCK = true,
}
local RECURSIVE_WRITE_METHODS = { MOVE = true, DELETE = true }

-- OPTIONS (capability negotiation -- reveals no repository content) and
-- MERGE (finalizes a commit whose per-path writes were already checked on
-- !svn/txr/... as they happened) never require a role grant, only that the
-- caller is authenticated at all -- which this module doesn't itself
-- enforce; that already happened in Apache's authentication phase, strictly
-- before the auth_checker phase this hook runs in, so by the time either of
-- these reaches authz_check_access() the caller is already a valid user.
-- Confirmed against a reference OpenIDC/mod_rewrite config already used in
-- production for this same role-claim approach, which grants both
-- unconditionally to any authenticated user (`Require valid-user` with no
-- `RequireAny`) -- and against real ra_serf client behavior: its first
-- request in a session (typically OPTIONS) is sent without credentials and
-- expects a 401-then-retry, not an outright 403 from a role it doesn't
-- have merely for asking what the server supports.
local EXEMPT_METHODS = { OPTIONS = true, MERGE = true }

-- Method -> access-type mapping, verified against mod_authz_svn.c's
-- req_check_access() (mod_authz_svn itself does gate OPTIONS on the read
-- role, unlike this module's deliberate EXEMPT_METHODS choice above). COPY
-- is the odd one out: it needs recursive *read* on its source (this
-- function's result), while its Destination header target always needs
-- recursive *write*, checked separately in authz_check_access() below.
function access_needed_for_method(method)
    if method == "COPY" then
        return { write = false, recursive = true }
    end
    if READ_METHODS[method] then
        return { write = false, recursive = false }
    end
    if RECURSIVE_WRITE_METHODS[method] then
        return { write = true, recursive = true }
    end
    if WRITE_METHODS[method] then
        return { write = true, recursive = false }
    end
    return { write = true, recursive = true }
end

-- Reads "<accs_dir>/<repo>.accs", written atomically by hooks/post-commit.
-- No in-process caching: mod_lua's Lua state (and any globals in it) can
-- persist and be reused across requests within a worker, which would risk
-- serving stale authorization decisions after an access-file update in a
-- security-sensitive check; the file is small, so re-reading it per
-- request is cheap enough to not be worth that risk.
function load_rules(accs_dir, repo)
    local f = io.open(accs_dir .. "/" .. repo .. ".accs", "r")
    if f == nil then
        return {}
    end
    local content = f:read("*a")
    f:close()
    return parse_access_file(content)
end

function authz_check_access(r)
    local location_prefix = r.subprocess_env["AUTHZ_LUA_LOCATION_PREFIX"] or "/svn"
    local accs_dir = r.subprocess_env["AUTHZ_LUA_ACCS_DIR"] or "/var/lib/subversion-auth/accs"
    local roles_var = r.subprocess_env["AUTHZ_LUA_ROLES_VAR"] or "AUTHZ_LUA_ROLES"

    local parsed = parse_svn_uri(r.uri, location_prefix)
    if parsed == nil then
        return OK
    end
    if parsed.legacy then
        r:debug("subversion-auth: refusing legacy DAV URI " .. r.uri)
        return HTTP_FORBIDDEN
    end

    local rules = load_rules(accs_dir, parsed.repo)
    local roles = parse_roles(r.subprocess_env[roles_var])

    local ok = true
    if parsed.path ~= nil and not EXEMPT_METHODS[r.method] then
        ok = check_access(rules, parsed.path, roles, access_needed_for_method(r.method))
    end

    if ok and (r.method == "COPY" or r.method == "MOVE") then
        local dest_header = r.headers_in["Destination"]
        if dest_header == nil then
            ok = false
        else
            local dest_parsed = parse_svn_uri(strip_scheme_host(dest_header), location_prefix)
            if dest_parsed == nil or dest_parsed.legacy or dest_parsed.path == nil then
                ok = false
            elseif dest_parsed.repo ~= parsed.repo then
                ok = false -- cross-repository copy/move is not supported
            else
                ok = check_access(rules, dest_parsed.path, roles, { write = true, recursive = true })
            end
        end
    end

    if not ok then
        r:debug("subversion-auth: denied " .. r.method .. " " .. r.uri)
        return HTTP_FORBIDDEN
    end
    return OK
end
