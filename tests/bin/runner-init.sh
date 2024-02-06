#!/bin/bash -ex

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: runner-init.sh <name>"
    exit 1
fi

if [ "$IMAGE" == "" ]
then
    IMAGE=jss-runner
fi

docker run \
    --name=${NAME} \
    --hostname=${HOSTNAME} \
    --detach \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v ${GITHUB_WORKSPACE}:${SHARED} \
    -i \
    ${IMAGE}

# Pause 5 seconds to let the container start up.
# The container uses /usr/sbin/init as its entrypoint which requires few seconds
# to startup. This avoids the following error:
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
sleep 5
