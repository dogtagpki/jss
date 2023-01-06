#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG BASE_IMAGE="registry.fedoraproject.org/fedora:34"
ARG COPR_REPO=""

################################################################################
FROM $BASE_IMAGE AS jss-builder

ARG COPR_REPO
ARG BUILD_OPTS

RUN dnf install -y dnf-plugins-core

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Import source
COPY . /tmp/src/
WORKDIR /tmp/src

# Build packages
RUN dnf install -y git rpm-build
RUN dnf builddep -y --spec jss.spec
RUN ./build.sh $BUILD_OPTS --work-dir=../build rpm

################################################################################
FROM $BASE_IMAGE AS jss-runner

ARG COPR_REPO

EXPOSE 389 8080 8443

RUN dnf install -y dnf-plugins-core

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Import packages
COPY --from=jss-builder /tmp/build/RPMS /tmp/RPMS/

# Install packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

# Install systemd to run the container
RUN dnf install -y systemd

CMD [ "/usr/sbin/init" ]
