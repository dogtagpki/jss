#!/bin/bash -e

# Don't run metadata check as we can't know the build host subdomain
# of CI runners in advance to add to an allow list

echo "Running RPMInspect on SRPM"
rpminspect-fedora -E metadata build/SRPMS/*.rpm

# Run RPMInspect on RPMs
for f in build/RPMS/*rpm; do
  echo "::group::Running RPMInspect on $f"
  rpminspect-fedora -E metadata,javabytecode "$f"
  echo "::endgroup::"
done
