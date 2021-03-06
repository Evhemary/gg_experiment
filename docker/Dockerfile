# build-env stage
ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION as build-env

MAINTAINER sadjad "https://github.com/Evhemary"

RUN apt-get update -qq
RUN apt-get install -y -q gcc-7 g++-7 libcap-dev libncurses5-dev \
                          libboost-dev libssl-dev autopoint help2man texinfo \
                          python3 python3-pip libhiredis-dev protobuf-compiler \
                          git libprotobuf-dev libcrypto++-dev texinfo automake \
                          libtool pkg-config python-minimal

RUN pip3 install python_magic
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 99
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-7 99

RUN mkdir /app
#COPY . /app/gg
RUN git clone https://github.com/Evhemary/gg_experiment.git /app/gg

ENV LANG C.UTF-8
ENV LANGUAGE C:en
ENV LC_ALL C.UTF-8

# sandbox-env stage
FROM build-env as sandbox-env

ENV PATH /app/gg/src/frontend:/app/gg/src/models:$PATH

# ggfunctions deps
RUN pip3 install boto3 numpy python_magic

# common deps
RUN apt-get install -y -q vim wget unzip

# deps for excamera and viddec examples
RUN apt-get install -y -q ffmpeg

# deps for LLVM example
#RUN apt-get install -y -q cmake
RUN wget https://cmake.org/files/v3.16/cmake-3.16.3-Linux-x86_64.tar.gz \
    && tar -zxvf cmake-3.16.3-Linux-x86_64.tar.gz \
    && mv cmake-3.16.3-Linux-x86_64 cmake-3.16.3 \
    && ln -sf /cmake-3.16.3/bin/* /usr/bin

WORKDIR /app/gg
