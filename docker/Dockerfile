# Base recipe (apache2 + subversion + libapache2-mod-svn on debian:trixie)
# taken from ~/GitHub/quarkus-svn-extension's Dev Service container, which
# already proved this combination works for serving mod_dav_svn. mod_lua
# ships inside the apache2-bin package itself on Debian (there is no
# separate libapache2-mod-lua package -- `a2enmod lua` is enough once
# apache2 is installed); this doesn't use mod_authz_svn/mod_cgid.
#
# Build from the repo root: docker build -f docker/Dockerfile -t subversion-auth-test .
FROM debian:trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 \
        apache2-utils \
        subversion \
        libapache2-mod-svn \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod dav dav_svn auth_basic authn_file lua \
    && echo "ServerName localhost" >> /etc/apache2/apache2.conf

RUN mkdir -p /var/svn/repos /etc/subversion /var/lib/subversion-auth/accs \
    && chown -R www-data:www-data /var/svn/repos /etc/subversion /var/lib/subversion-auth

COPY docker/svn-httpd.conf /etc/apache2/sites-available/000-default.conf
COPY docker/test-roles.lua /opt/subversion-auth/docker/test-roles.lua
COPY mod-lua/svn-authz.lua /opt/subversion-auth/mod-lua/svn-authz.lua
COPY hooks/post-commit /opt/subversion-auth/hooks/post-commit
RUN chmod +x /opt/subversion-auth/hooks/post-commit

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint-svn.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-svn.sh

EXPOSE 80

ENTRYPOINT ["docker-entrypoint-svn.sh"]
