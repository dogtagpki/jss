#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG BASE_IMAGE="registry.fedoraproject.org/fedora:latest"
ARG COPR_REPO="@pki/master"

################################################################################
FROM $BASE_IMAGE AS jss-base

RUN dnf install -y systemd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD [ "/usr/sbin/init" ]

################################################################################
FROM jss-base AS jss-builder

ARG COPR_REPO
ARG BUILD_OPTS

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import source
COPY . /tmp/src/
WORKDIR /tmp/src

# Build packages
RUN dnf install -y git rpm-build
RUN dnf builddep -y --spec jss.spec
RUN ./build.sh $BUILD_OPTS --work-dir=../build rpm

################################################################################
FROM jss-base AS jss-runner

ARG COPR_REPO

EXPOSE 389 8080 8443

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import packages
COPY --from=jss-builder /tmp/build/RPMS /tmp/RPMS/

# Install packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

CMD [ "/usr/sbin/init" ]
