FROM ubuntu:latest

RUN apt update && apt -y upgrade

# Prevent tzdata issuing console prompt
ENV DEBIAN_FRONTEND=noninteractive
RUN apt install -y git tzdata cmake build-essential

# Create a workarea
RUN mkdir build
WORKDIR /build

# Acquire and build BearSSL library
RUN git clone https://www.bearssl.org/git/BearSSL
WORKDIR /build/BearSSL
RUN make
RUN cp -v ./build/libbearssl.a /usr/local/lib
RUN cp -v ./inc/*.h /usr/local/include

# Acquire and build MQTT-C library
WORKDIR /build
RUN git clone https://github.com/LiamBindle/MQTT-C
WORKDIR /build/MQTT-C
RUN mkdir build
WORKDIR /build/MQTT-C/build
RUN cmake .. -DMQTT_C_BearSSL_SUPPORT=yes -DMQTT_C_EXAMPLES=no
RUN make
RUN cp -v ./libmqttc.a /usr/local/lib
RUN cp -v ../include/*.h /usr/local/include

# Acquire and build Azure SDK for C libraries
WORKDIR /build
#RUN git clone --branch azure-sdk-for-c_1.0.0-preview.3 https://github.com/azure/azure-sdk-for-c.git
RUN git clone --branch 1.3.2 https://github.com/Azure/azure-sdk-for-c.git
WORKDIR /build/azure-sdk-for-c
RUN mkdir build
WORKDIR /build/azure-sdk-for-c/build
RUN cmake .. -DAZ_PLATFORM_IMPL=POSIX
RUN make
WORKDIR /build/azure-sdk-for-c
RUN mkdir /usr/local/include/azure
RUN cp -r -v sdk/inc/azure/* /usr/local/include/azure
RUN find . -iname "lib*.a" -exec cp -v {} /usr/local/lib \;

# All required libraries and headers have been copied to /usr/local/lib and /usr/local/include

# Acqure and build the sample
WORKDIR /build
RUN git clone -b latest_branch https://github.com/markrad/Azure-Embedded-IoT-C-Sample.git
WORKDIR /build/Azure-Embedded-IoT-C-Sample
RUN mkdir build
WORKDIR /build/Azure-Embedded-IoT-C-Sample/build
RUN cmake ..
RUN make

ADD ./certs.pem ./