## MQTT publish Subscribe Demo

### Introduction
This example demonstrates an MQTT publish subscribe task running concurrently with Over-The-Air firmware update background task, using coreMQTT agent libary to manage the thread safety for the MQTT connection.The publish subscribe task runs in a loop to publish a message to AWS IoT MQTT broker on a topic, and echoes back the same message, by subscribing to the same topic with the broker. OTA firmware update task runs OTA Agent loop which polls for and subscribes to OTA job requests from AWS IoT OTA service. The OTA agent task receives firmware chunks and sends control packets over MQTT, concurrently using coreMQTT agent task for thread safety.

### Hardware requirements

- Mini/micro USB cable
- MIMXRT1060-EVKB board
- OM-SE050ARD Development kit
- Personal Computer with Windows platform
- Network cable RJ45 standard (Network with Internet access)

### ToolChain Requirements

- MCUXpresso IDE
- python3 and pip

### Board Setup

1. Plug in the OM-SE050ARD development kit to arduino headers on the MIMXRT1060-EVKB board.
3. Connect the USB cable between the personal computer and open SDA USB port (J1) on the board.
2. Connect the RJ45 cable to the ethernet port.

### Preparing the demo

#### Setting up the bootloader project

The demo contains firmware over the air updates functionality for which the secure bootloader is required. To setup, build and flash bootloader project see the README.

#### Setting up the demo project

1. Open the MCUXpresso IDE and choose the repository root path as the workspace path.
2. Click on `File` then `Open Projects from the FileSystem`. Choose the project from folder `projects/evkmimxrt1060/pubsub`. Import the project into the workspace.
3. Build and flash the demo from the IDE.
4. The project is configured to flash the demo to an address known to the bootloader. To boot a new application image from IDE, we have to jump start the application from the debugger. To do so:
   a. Launch the application as normal from the debugger IDE. The debugger goes into an endless loop after flashing the image.
   b. Pause the debugger. Go to `Debugger Console` in the bottom pane and type `jump ResetISR` to jump to application starting address. From then, application   execution can be continued normally.

### Device Provisioning

The project requires a one time setup of MQTT broker endpoint and device credentials required for connecting to AWS IoT core, and also the thing name by which the device is registered with AWS IoT.

1. By default the project boots into a provision mode at startup where all the configuration can be setup. The provisioning mode can be controlled using the flag `appmainPROVISIONING_MODE` in `examples/evkbmimxrt1060/pubsub/app_main.c`.
2. The provisioning mode waits for user input commands from a CLI task. 
3. Connect to the USB port using a serial terminal of the choice.
4. Run the following command to get the  pre-provisioned X.509 certificate from secure element:
```
pki get cert sss:F0000001
```
`sss:F0000001` is the slot where the certificate is stored in secure element.
5. Copy the PEM certificate from console and register the certificate with AWS IoT without a CA using doc [here](https://docs.aws.amazon.com/iot/latest/developerguide/manual-cert-registration.html#manual-cert-registration-console-noca).
6. Get the AWS IoT MQTT broker endpoint from `Settings` tab in AWS IoT console. Provision the endpoint by executing the following command:
```
conf set ENDPOINT <endpoint string>
```
7. Create a new thing, device policy in AWS as mentioned in the doc [here](https://docs.aws.amazon.com/iot/latest/developerguide/create-iot-resources.html). Attach the certificate registered in step 5 with the thing name. Provision the new thing name to the device:
```
conf set THINGNAME <thing name>

8. Once the configurations are setup turn off the provisioning mode by setting `appmainPROVISIONING_MODE` to `0` and then recompiling and flashing the image onto the board.

### Runnning the demo

The device should be successfully provisioned at this time. Provisioning mode should be turned off by seting `appmainPROVISIONING_MODE` to `0` in `examples/evkbmimxrt1060/pubsub/app_main.c`.  Demo on startup, establishes a TLS connection with AWS IoT MQTT broker and runs the publish subscribe demo task using coreMQTT agent. The demo also runs the OTA firmware update task in the background polling for the firmware update jobs from AWS IoT service. 
