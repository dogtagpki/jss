#!/bin/bash

NAME=$1
URL=$2

if [ "$NAME" == "" ] || [ "$URL" == "" ]
then
    echo "Usage: tomcat-start-wait.sh <name> <URL>"
    exit 1
fi

if [ "$MAX_WAIT" == "" ]
then
    MAX_WAIT=60 # seconds
fi

start_time=$(date +%s)

while :
do
    sleep 1

    if [ ! "$(docker exec "$NAME" curl -IkSs "$URL")" ]
    then
        break
    fi

    current_time=$(date +%s)
    elapsed_time=$(("$current_time" - "$start_time"))

    if [ "$elapsed_time" -ge "$MAX_WAIT" ]
    then
        echo "Tomcat did not start after ${MAX_WAIT}s"
        exit 1
    fi

    echo "Waiting for Tomcat to start (${elapsed_time}s)"
done

echo "Tomcat is started"