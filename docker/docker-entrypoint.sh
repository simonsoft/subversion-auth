#!/bin/sh
# Adapted from ~/GitHub/quarkus-svn-extension's entrypoint: creates the
# htpasswd file for the fixed set of test users (see docker/test-roles.lua)
# on first start, then runs Apache in the foreground.
set -eu

if [ ! -f /etc/subversion/passwd ]; then
    htpasswd -bc /etc/subversion/passwd devuser devpass
    htpasswd -b /etc/subversion/passwd readeruser readpass
    chown www-data:www-data /etc/subversion/passwd
fi

rm -f /var/run/apache2/apache2.pid

exec apache2ctl -D FOREGROUND
