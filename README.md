# Azure-Embedded-IoT-C-Sample
This is a sample application built using the [Azure Embedded C SDK](https://github.com/Azure/azure-sdk-for-c) to connect and interact with an Azure IoT hub. Currently this is a work in progress with some missing features. 
## Implemented
- Generate a valid SAS token from a connection string
- Connect to the IoT hub
- Send Telemetry to the IoT hub
- Receive C2D messages from the IoT hub (but just prints them out)
- Receive and action two device methods :- interval and kill

## Not Implemented
- No support for device twins
- Reconnection logic is missing
- Error handling probably leaves something to be desired

## Components
I avoided using components that have been used in provided samples. I wanted to make this an alternative to those samples in order to gain an appreciation about what it takes to build one of these applications. I choose to use:
- TLS Library: [BearSSL](https://bearssl.org)
- MQTT Library: [MQTT-C](https://github.com/LiamBindle/MQTT-C). However, please note that I have an outstanding pull request against that repository to include support for BearSSL. Currently it uses my [fork](https://github.com/markrad/MQTT-C).

## Building
This code is currently only designed to run on Linux.

1. Download BearSSL, make and install.
2. Clone MQTT-C and build. Remember where the binaries are because you'll need to hack the CMakeLists.txt to pick it up during the link.
3. Clone this sample and do a typically cmake build. 
## Running the Application
You will need to provide at least two and optionally three environment variables in order to run the application. These are:
- **AZ_IOT_CONNECTION_STRING** The connection string for the device you wish to connect
- **AZ_IOT_DEVICE_X509_TRUST_PEM_FILE** The filename of the PEM format certificates that will be used to validate the server's certificate. This is the trusted root certificate.
- **AZ_IOT_DEVICE_SAS_TTL** Optionally the SAS token time to live value in seconds. This will default to 3600 if omitted.
## To do
- Add device twin capablilities
- Add reconnection logic
- Review and improve error handling
- Create an easier mechanism to build and run the code.
