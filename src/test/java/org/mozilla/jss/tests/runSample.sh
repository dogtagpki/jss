#!/usr/bin/bash

# NOTE: Read the notes at the top of bbenv.sh on how to set things up for
#       different systems

# define a COMPILER_TAG to sync NSS and JSS 'OBJDIR_NAME' directory names
export COMPILER_TAG=_gcc
export NSPR_DS_INCLUDE=`pwd`/hg/nspr/lib/ds
export RUN_BITS=64
export RUN_OPT=DBG
export ENVVARS=`pwd`/bbenv.sh

# --test-nss
./hg/nss/automation/buildbot-slave/build.sh --build-nss --build-jss --test-jss --nojsssign
