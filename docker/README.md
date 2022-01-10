# Docker Setup for Pyshark

The **`pyshark`** Python package has a dependency on the `lxml` package which
has in some instances caused installation problems on Docker, for example due
to upstream dependencies on `cryptography` and **Rust**. From time to time,
security vulnerabilities may be found requiring an update to the image.

This `pyshark.Dockerfile` and `docker-build` script can be used on a development
platform that has Docker [**`buildx`**](https://github.com/docker/buildx)
installed, which it is by default on Docker Desktop for Windows or Mac.

To rebuild the `fieldedge-pyshark` docker image you can login to Docker Hub if
you are an authorized user/member of the **inmarsat** organization, and then
run the build script:
```
$ docker login
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: myinmarsatdockerhubusername
Password:
Login Succeeded
$ bash docker-build.sh
```
>It may take several minutes to rebuild the images, the longest part being
creation of the lxml wheel.