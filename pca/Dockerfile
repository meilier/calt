FROM ubuntu:latest
RUN apt-get update --fix-missing && apt-get install -y \
    g++ \
    make \
    vim \
    tree \
    git \
    openssl
RUN cd / && git clone https://github.com/meilier/pca.git \
    && rm /bin/sh \
    && ln -s /bin/bash /bin/sh