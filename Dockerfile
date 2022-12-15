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
FROM jss-base AS jss-deps

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Install JSS runtime dependencies
RUN dnf install -y dogtag-jss \
    && dnf remove -y dogtag-* --noautoremove \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM jss-deps AS jss-builder-deps

# Install build tools
RUN dnf install -y rpm-build

# Import JSS sources
COPY jss.spec /root/jss/
WORKDIR /root/jss

# Install JSS build dependencies
RUN dnf builddep -y --spec jss.spec

################################################################################
FROM jss-builder-deps AS jss-builder

# Import JSS source
COPY . /root/jss/

# Build JSS packages
RUN ./build.sh --work-dir=build rpm

################################################################################
FROM jss-deps AS jss-runner

# Import JSS packages
COPY --from=jss-builder /root/jss/build/RPMS /tmp/RPMS/

# Install JSS packages
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS
