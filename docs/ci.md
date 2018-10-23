# Containers and Continuous Integration

JSS uses [Travis CI](https://travis-ci.org/dogtagpki/jss) for PR gating. We use
Linux containers to ensure a consistent build environment and to allow us
to test locally and in Travis on various platforms.


## Running CI Locally

The Docker images are built in Travis using the Dockerfiles in
`tools/Dockerfiles`; they are not pushed to DockerHub or similar platforms
at this time. To test locally, we recommend using the provided container
tool, `tools/run_container.sh`.

For a brief example:

```bash
cd /path/to/sandbox/jss
./tools/run_container.sh fedora_28
```

Note that this requires either Buildah and Podman or Docker to be installed.

For more extensive documentation, please refer to the
[Buildah](https://github.com/containers/buildah/blob/master/docs/) and
[Podman docs](https://github.com/containers/libpod/tree/master/docs) and
the code in the `tools/run_container.sh` script.


## Skipping CI

To skip running CI for a given commit (e.g., for updating documentation),
append `[skip ci]` to the commit summary. Note that the `ubuntu_jdk8` image
does not affect build status; it is included for reference only.
