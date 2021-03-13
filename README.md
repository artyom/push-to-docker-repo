# push-to-docker-repo

This is an example program demonstrating how to construct and push Docker
images to a docker repository only using the Go standard library.

It is an approximate equivalent of packing static linux/amd64 Go binary to a
"FROM scratch" docker container, and pushing this container to a docker
repository, like so:

    FROM scratch
    ADD main /hello-from-container
    CMD ["/hello-from-container"]

This program reads registry authentication token from
`${HOME}/.docker/config.json` file.
