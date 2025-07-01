#!/bin/bash -e

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --image=<image>          Container image (default: jss-runner)"
    echo "    --hostname=<hostname>    Container hostname"
    echo "    --network=<network>      Container network"
    echo "    --network-alias=<alias>  Container network alias"
    echo " -v,--verbose                Run in verbose mode."
    echo "    --debug                  Run in debug mode."
    echo "    --help                   Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        image=?*)
            IMAGE="$LONG_OPTARG"
            ;;
        hostname=?*)
            HOSTNAME="$LONG_OPTARG"
            ;;
        network=?*)
            NETWORK="$LONG_OPTARG"
            ;;
        network-alias=?*)
            ALIAS="$LONG_OPTARG"
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        suffix* | base-dn*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$NAME" == "" ]
then
    echo "ERROR: Missing container name"
    exit 1
fi

if [ "$IMAGE" == "" ]
then
    IMAGE=jss-runner
fi

if [ "$DEBUG" = true ]
then
    echo "NAME: $NAME"
    echo "IMAGE: $IMAGE"
    echo "HOSTNAME: $HOSTNAME"
    echo "NETWORK: $NETWORK"
    echo "ALIAS: $ALIAS"
fi

OPTIONS=()
OPTIONS+=(--name "$NAME")
OPTIONS+=(--hostname "$HOSTNAME")

# Allows the execution of executable binaries in /tmp.
# This is required to build PKI with Maven.
# https://docs.docker.com/engine/storage/tmpfs/
OPTIONS+=(--tmpfs /tmp:exec)

OPTIONS+=(--tmpfs /run)
OPTIONS+=(-v "$GITHUB_WORKSPACE:$SHARED")

# required to run Podman in container
OPTIONS+=(-v /var/lib/containers:/var/lib/containers)

OPTIONS+=(--detach)
OPTIONS+=(--privileged)
OPTIONS+=(-i)

if [ "$NETWORK" != "" ]
then
    OPTIONS+=(--network "$NETWORK")
fi

if [ "$ALIAS" != "" ]
then
    OPTIONS+=(--network-alias "$ALIAS")
fi

if [ "$VERBOSE" = true ]
then
    echo "Starting $NAME container"
fi

docker run "${OPTIONS[@]}" $IMAGE "/usr/sbin/init"

# Pause 5 seconds to let the container start up.
# The container uses /usr/sbin/init as its entrypoint which requires few seconds
# to startup. This avoids the following error:
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
sleep 5
