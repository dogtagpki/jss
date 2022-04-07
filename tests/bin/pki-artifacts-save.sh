#!/bin/bash

CONTAINER=$1
INSTANCE=$2

if [ "$INSTANCE" == "" ]
then
    INSTANCE=pki-tomcat
fi

ARTIFACTS=/tmp/artifacts/$CONTAINER

mkdir -p $ARTIFACTS/etc/pki/$INSTANCE
mkdir -p $ARTIFACTS/var/log/pki/$INSTANCE

docker exec $CONTAINER ls -la /etc/pki
docker cp $CONTAINER:/etc/pki/pki.conf $ARTIFACTS/etc/pki
docker cp $CONTAINER:/etc/pki/$INSTANCE $ARTIFACTS/etc/pki

docker exec $CONTAINER ls -la /var/log/pki
docker cp $CONTAINER:/var/log/pki $ARTIFACTS/var/log
docker exec $CONTAINER journalctl -u pki-tomcatd@$INSTANCE.service > $ARTIFACTS/var/log/pki/$INSTANCE/systemd.log
