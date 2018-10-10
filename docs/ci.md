# Containers and Continuous Integration

JSS uses [Travis CI](https://travis-ci.org/dogtagpki/jss) for PR gating. We use
Linux containers to ensure a consistent build environment and to allow us
to test locally and in Travis on various platforms.

The Docker images are built in Travis using the Dockerfiles in
`tools/Dockerfiles`; they are not pushed to DockerHub or similar platforms
at this time. To test locally, we recommend using `buildah` and `podman`.
For a brief example:

```bash
cd /path/to/sandbox/jss
export BASE_IMAGE=fedora_28
buildah bud --tag jss_$BASE_IMAGE:latest -f tools/Dockerfiles/$BASE_IMAGE . 
podman run jss_$BASE_IMAGE:latest
```

For more extensive documentation, please refer to the
[Buildah](https://github.com/containers/buildah/blob/master/docs/) and
[Podman docs](https://github.com/containers/libpod/tree/master/docs).

To skip running CI for a given commit (e.g., for updating documentation),
append `[skip ci]` to the commit summary. Note that the `ubuntu_jdk8` image
does not affect build status; it is included for reference only.
