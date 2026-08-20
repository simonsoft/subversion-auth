-- TEST-ONLY harness script -- not part of the production module.
--
-- Stands in for the real upstream authentication module (e.g.
-- mod_auth_openidc) that a production deployment relies on to populate
-- AUTHZ_LUA_ROLES_VAR from a validated token claim. Registered as an
-- *earlier* LuaHookAuthChecker than mod-lua/svn-authz.lua's (see
-- docker/svn-httpd.conf), so it runs first: by that point r.user is
-- already populated by mod_auth_basic's check_user_id handling (which
-- always runs before the auth_checker phase), so this just maps the
-- already-authenticated username to a fixed set of test roles and defers
-- the actual authorization decision to svn-authz.lua.
--
-- Critically, that means returning DECLINED (-1, Apache's own httpd.h
-- value), not OK: auth_checker hooks run in AP_IMPLEMENT_HOOK_RUN_FIRST
-- order, so returning OK here would be treated as an authoritative "access
-- granted" and stop the chain right here, before svn-authz.lua's hook ever
-- runs -- confirmed the hard way, by watching every request get allowed
-- regardless of what the real module decided until this returned DECLINED
-- instead. (mod_lua's "apache2" module is empty for LuaHookAuthChecker
-- hooks, confirmed against a real build, hence the plain httpd.h literal
-- rather than e.g. apache2.DECLINED.)
--
-- This script exists because the integration tests drive the real `svn`
-- CLI, which only ever sends credentials as HTTP Basic Auth -- there's no
-- way for it to carry an arbitrary role claim directly.
local TEST_USER_ROLES = {
    devuser = "developers",
    readeruser = "readers",
}

function assign_test_roles(r)
    r.subprocess_env["AUTHZ_LUA_ROLES"] = TEST_USER_ROLES[r.user] or ""
    return -1
end
