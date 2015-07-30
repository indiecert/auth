# Introduction
These are all the files to get a Docker instance running with 
IndieCert.

To build the Docker image:

    $ sudo docker build -t fkooman/indiecert .

To run the container:

    $ sudo docker run -h indiecert.example -d -p 443:443 -p 80:80 fkooman/indiecert

That should be all. You can replace `fkooman` with your own name of course.

Put the following in `/etc/hosts`:

    127.0.0.1      indiecert.example

Now go to [https://indiecert.example](https://indiecert.example).

To run an interactive shell in the Docker container:

    docker exec -it <container_id> /bin/bash
