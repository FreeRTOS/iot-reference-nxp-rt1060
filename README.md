## IoT Refrence Integration on NXP IMX RT1060 MCU and EdgeLock SE050 Secure Element


### Introduction
The project demonstrates how to create reference IoT applications by integrating FreeRTOS modular software with hardware capabilities of IMXRT1060 ARM Cortex M7 MCU and enhanced security features of Edgelock SE050 secure element. The project contains reference implementations that shows different IoT application tasks which runs concurrently and securely communicate with AWS IoT. The implementation also shows how to perform over-the-air firmware updates leveraging AWS IoT OTA service and secure bootloader capabilities from MCUBoot. The reference implementation runs on MIMRT1060-EVKB evaluation board and OEMSE050ARD secure element kit.

### Features

#### Secure TLS Communication with mutual authentication

The project leverages EdgeLock SE050 secure element to securely store X.509 Certificate and credentials used to create a TLS communication with MQTT broker. TLS connection enforces mutual authentication by verifying the server certificate using pre-provisioned CA certificate from AWS IoT MQTT broker. The secure element contains unique pre-provisioned credentials and X.509 certificate securely stored in hardware memory. The X.509 certificate can be retrieved through a secure authenticated channel with the MCU and registered with AWS IoT to create a secure connection with the cloud.

#### Secure Over-the-air firmware updates

Firmware update is provided by AWS IoT OTA service for FreeRTOS. The OTA client library downloads firmware chunks over a mutually authenticated TLS connection with MQTT broker, and performs code signature verification of the entire image before boot. The public key used for code signature verification is provisioned in EdgeLock SE050 secure element. User can store the private key securely in their premises to sign the image or manage them in AWS account and create a code signing job along with OTA.
Hardware root of trust verification is provided using a two stage bootloading process. A small first stage ROM bootloader performs signature verifcation of an immutable second stage bootloader using the keys stored in One Time Programmable (OTP) memory . The second stage bootloader is implemented using open source MCUBoot, which performs application image signature verification and encryption. Key pair for MCUBoot signature verification is generated at time of preparing the bootloader. Private key is stored securely in customer premise and the public key for verification is emebedded into the bootloader.

#### Application multitasking using coreMQTT Agent
The project shows how to run multiple demo IoT application tasks concurrently using coreMQTT agent task. CoreMQTT agent manages the MQTT connection and performs serialization of MQTT messages from different tasks, over a single TLS connection to MQTT broker.


### Folder Structure

The folder inside the repository is organized as follows:

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

#### Cloning the Repository

To clone using HTTPS:
```
git clone https://github.com/FreeRTOS/lab-iot-reference-nxp-rt1060.git --recurse-submodules
```
Using SSH:

```
git clone git@github.com:FreeRTOS/lab-iot-reference-nxp-rt1060.git --recurse-submodules
```

If you have downloaded the repo without using the `--recurse-submodules` argument, you need to run:

```
git submodule update --init --recursive
```

#### Running the demo

To get started running a coreMQTT Agent demo that publishes and subscribes messages with AWS IoT MQTT broker, along with over-the-air updates functionality, see the [README](https://github.com/FreeRTOS/lab-iot-reference-nxp-rt1060/blob/main/examples/evkbmimxrt1060/pubsub/README.md).


### License

Example source code under `./examples/` and libraries under `./Middleware/AWS` and ./Middleware/FreeRTOS are licensed under the MIT-0 License. See the `LICENSE` file. For all other source code licenses including `core/` and `Middleware/NXP` folders, see source header documentation.
