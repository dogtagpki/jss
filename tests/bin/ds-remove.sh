#!/usr/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --image=<image>          Container image (default: quay.io/389ds/dirsrv)"
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
        image*)
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

NAME=$1

if [ "$NAME" == "" ]
then
    echo "ERROR: Missing container name"
    exit 1
fi

if [ "$IMAGE" = "" ]
then
    IMAGE=quay.io/389ds/dirsrv
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "IMAGE: $IMAGE"
fi

remove_server() {
    if [ "$VERBOSE" = true ] ; then
        echo "Removing DS server"
    fi

    docker exec $NAME dsctl slapd-localhost remove --do-it

    if [ "$VERBOSE" = true ] ; then
        echo "Removing DS container"
    fi

    docker rm $NAME > /dev/null

    echo "DS server has been removed"
}

remove_container() {
    if [ "$VERBOSE" = true ] ; then
        echo "Stopping DS container"
    fi

    docker stop $NAME > /dev/null

    if [ "$VERBOSE" = true ] ; then
        echo "Removing DS container"
    fi

    docker rm $NAME > /dev/null

    if [ "$VERBOSE" = true ] ; then
        echo "Removing DS volume"
    fi

    docker volume rm $NAME-data > /dev/null

    echo "DS container has been removed"
}

if [ "$IMAGE" = "jss-runner" ]
then
    remove_server
else
    remove_container
fi
