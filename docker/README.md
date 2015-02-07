# Introduction
These are all the files to get a Docker instance running with 
`php-relmeauth-service`.

To build the Docker image:

    docker build --rm -t fkooman/indiecert .

To run the container:

    docker run -d -p 443:443 -p 80:80 fkooman/indiecert

That should be all. You can replace `fkooman` with your own name of course.

Put the following in `/etc/hosts`:

    127.1.2.3      indiecert.net

Now go to [https://indiecert.net](https://indiecert.net).

To run an interactive shell in the Docker container:

    docker exec -it <container_id> /bin/bash
