# Introduction
These are all the files to get a Docker instance running with 
IndieCert.

To build the Docker image:

    docker build --rm -t fkooman/indiecert .

To run the container:

    docker run -h indiecert.example.org -d -p 443:443 -p 80:80 fkooman/indiecert

That should be all. You can replace `fkooman` with your own name of course.

Put the following in `/etc/hosts`:

    127.0.0.1      indiecert.example.org

Now go to [https://indiecert.example.org](https://indiecert.example.org).

To run an interactive shell in the Docker container:

    docker exec -it <container_id> /bin/bash
