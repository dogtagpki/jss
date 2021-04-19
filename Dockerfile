#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG OS_VERSION="latest"
ARG COPR_REPO="@pki/master"

################################################################################
FROM registry.fedoraproject.org/fedora:$OS_VERSION AS jss-builder

ARG COPR_REPO
ARG BUILD_OPTS

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import JSS sources
COPY . /tmp/jss/
WORKDIR /tmp/jss

# Build JSS packages
RUN dnf install -y rpm-build
RUN dnf builddep -y --spec jss.spec
RUN ./build.sh $BUILD_OPTS --work-dir=build rpm

################################################################################
FROM registry.fedoraproject.org/fedora:$OS_VERSION AS jss-runner

ARG COPR_REPO

EXPOSE 389 8080 8443

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import JSS packages
COPY --from=jss-builder /tmp/jss/build/RPMS /tmp/RPMS/

# Install JSS packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

# Install systemd to run the container
RUN dnf install -y systemd

CMD [ "/usr/sbin/init" ]
