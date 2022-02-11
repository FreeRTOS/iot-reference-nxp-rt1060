## IoT Refrence Integration on NXP IMX RT1060 MCU and EdgeLock SE050 Secure Element


### Introduction
The project demonstrates how to create reference IoT applications by integrating FreeRTOS modular software with hardware capabilities and enhanced security features provided by NXP's IMXRT1060 ARM Cortex M7 MCU and Edgelock SE050 secure element. The project contains demo implementations which runs on MIMXRT1060-EVK evaluation kit. Demo showcases multiple IoT application tasks thar run concurrently and securely communicates with AWS IoT and perform secure over the air firmware updates leveraging opensource MCUBoot bootloader capabilities.


### Features

#### Secure TLS Communication with mutual authentication

The project leverages EdgeLock SE050 secure element to store the X509 Certificate and private key used to create a secure TLS communication with MQTT broker. The TLS communication enforces mutual authentication by verifying server certificate using the CA certificate from AWS IoT MQTT broker. Edgelock SE050 comes preprovisioned with the device credentials and X509 certificate for the TLS connection. X509 certificate can be retrieved from the secure element and registered with AWS account prior to device establishing TLS connection with AWS IoT MQTT broker.


#### Secure Over the air updates
Secure OTA download is provided by AWS IoT OTA service for FreeRTOS. OTA client library provided downloads firmware over a mutually authenticated TLS connection with MQTT broker, and performs inbuilt code signing verification. The public key used for code signing verification is provisioned in EdgeLock SE050 secure element. User can store the private key securely in their premises to sign the image or provision them in AWS account and create a code signing job along with OTA.
Hardware root of trust verification is provided using a two stage bootloading process. A small first stage ROM bootloader performs signature verifcation of an immutable second stage bootloader using the Hash and keys stored in One Time Programmable memory (OTP). The second stage bootloader is implemented using open source MCUBoot, which performs application image signature verification and encryption. Key Pair for MCUBoot signature verification is generated at time of preparing the bootloader. Private key is stored securely in customer premise and the public key for verification is emebedded into the bootloader.

#### IoT Application Multitasking using coreMQTT Agent
The project shows how to run multiple demo IoT application tasks concurrently using coreMQTT agent task. CoreMQTT agent manages the MQTT connection and performs serialization of MQTT messages from different tasks, over a single TLS connection to MQTT broker.


### Folder Structure

The folder structure for the repo is organized as follows:

```
|— core/
|- Middleware/
   |- NXP/
   |- AWS/
   |- FreeRTOS/
   |- third_party libs
|- examples/
  |- evkbmimxrt1060/ 
  |_ common/
|- projects/
   |_evkbmimxrt1060/ 
|- README.md
|_ LICENSE
```
Root of the repository contains following top level folders:
1. `core` submodules to NXP's MCUX SDK repository. The repository hosts the MCUXpresso software development package which contains ARM CMSIS core files, board support packages for devices, shared peripheral drivers and components.
2. `Middleware` folder hosts NXPs middleware SDKs such as Plug and Trust Middleware stack, FreeRTOS Kernel and modular software libraries, AWS connectivity libraries, and other third party libraries required for the project.
3. `examples` folder hosts the IoT reference sample for the board. The common demo tasks such as MQTT Agent, OTA Agent which are shared across different board examples are placed under `common` folder. Folder `evkbmimxrt1060` contains each of demo samples for the board.
4. `projects` folder contains MCUXpresso IDE projects for the examples provided. Currently all projects are tested on MCUXpresso IDE on windows platform.

### Getting Started

To get started running a coreMQTT Agent demo that publishes and subscribes messages with AWS IoT MQTT broker, along with over-the-air updates functionality, see the [README](https://github.com/FreeRTOS/lab-iot-reference-nxp-rt1060/blob/main/examples/evkbmimxrt1060/pubsub/README.md).


### License

Example source code under `./examples/` and libraries under `./Middleware/AWS` and ./Middleware/FreeRTOS are licensed under the MIT-0 License. See the LICENSE file. For all other source code licenses including core/ and Middleware/NXP folders, see source header documentation.
