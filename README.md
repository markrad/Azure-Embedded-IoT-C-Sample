# Azure-Embedded-IoT-C-Sample
This is a sample application built using the [Azure Embedded C SDK](https://github.com/Azure/azure-sdk-for-c) to connect and interact with an Azure IoT hub. Currently this is a work in progress with some missing features. 
## Implemented
- Authenticate with either a SAS token or an X.509 certificate
- Connect to the IoT hub
- Send Telemetry to the IoT hub
- Receive C2D messages from the IoT hub (but just prints them out)
- Receive and action two device methods :- interval and kill
- Reconnection logic
- Device twins that allow one to modify the telemetry interval

## Not Implemented
- Error handling probably leaves something to be desired (but is getting better)

## Components
I avoided using components that have been used in provided samples. I wanted to make this an alternative to those samples in order to gain an appreciation about what it takes to build one of these applications. I choose to use:
- TLS Library: [BearSSL](https://bearssl.org)
- MQTT Library: [MQTT-C](https://github.com/LiamBindle/MQTT-C). 

## Building
This code is currently only designed to run on Linux. Briefly you will need to:

1. Clone BearSSL, make and copy libbearssl.a and all the headers to a known location.
2. Clone MQTT-C, cmake, make and copy libmqttc.a and all the headers to a known location.
3. Clone the Azure SDK for C, cmake, make and copy libraries and headers to a known location
3. Clone this sample and do a typicall cmake build. 

For more detailed build instructions, you will find the entire process encapsulated in the dockerfile contained within. This will build everything above and can be used as is or as a guide to complete the steps at your console.
## Running the Application
The application configures itself from values provided in the environment. There are:
- **AZ_IOT_CONNECTION_STRING** _Required_: The connection string for the device you wish to connect. If this contains x509=true then you must also provide _AZ_IOT_DEVICE_X509_CLIENT_PEM_FILE_ and _AZ_IOT_DEVICE_X509_CLIENT_KEY_FILE_ as described below.
- **AZ_IOT_DEVICE_X509_TRUST_PEM_FILE** _Required_: The filename of the PEM format certificates that will be used to validate the server's certificate. This is the trusted root certificate.
- **AZ_IOT_DEVICE_SAS_TTL** _Optional_: The SAS token time to live value in seconds. This will default to 3600 if omitted.
- **AZ_IOT_DEVICE_X509_CLIENT_PEM_FILE** _Required when using X.509 authentication_: An X.509 certificate file name that contains the client's certificate for authentication.
- **AZ_IOT_DEVICE_X509_CLIENT_KEY_FILE** _Required when using X.509 authentication_: The X.509 private key file name for the above. 
## To do
- Review and improve error handling
- Review memory usage in X.509 validation
