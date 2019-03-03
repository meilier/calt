FROM ubuntu:xenial
# COPY sources.list /sources.list
# RUN cp /sources.list /etc/apt/sources.list
RUN apt-get update --fix-missing && apt-get install -y \
    software-properties-common \
    apt-transport-https \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && apt-get update \
    && apt-get install -y \
    gcc-7 \
    g++-7 \
    cmake \
    make \
    libboost-all-dev
RUN apt-get install -y git
RUN cd /usr/bin && rm -rf gcc && ln -sf gcc-7 gcc
RUN cd /usr/bin && rm -rf gcc-ar && ln -sf gcc-ar-7 gcc-ar
RUN cd /usr/bin && rm -rf gcc-nm && ln -sf gcc-nm-7 gcc-nm
RUN cd /usr/bin && rm -rf gcc-ranlib && ln -sf gcc-ranlib-7 gcc-ranlib
RUN cd /usr/bin && rm -rf g++ && ln -sf g++-7 g++
# RUN cd / && git clone https://github.com/Hadigan/Breep.git
COPY ./ /calt
RUN cd /calt && mkdir build && cd build && cmake .. && make 