IoT Reference Integration:
on the NXP i.MX RT1060 MCU and EdgeLock® SE050 Secure Element
========

## 1 Prerequisites

### 1.1 Hardware Requirements

* Mini/micro USB cable
* MIMXRT1060-EVKB board. To order, visit
    [MIMXRT1060-EVKB Buying Options](https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/i-mx-rt1060-evaluation-kit:MIMXRT1060-EVK).
    *Note: The projects and instructions here are validated on MIMXRT1060-EVKB board only.*
* OM-SE050ARD Development kit. To order, visit [OM-SE050ARD Buy Options](https://www.nxp.com/part/OM-SE050ARD#/).
* Personal Computer with the Windows platform.
* Network cable RJ45 standard (Network with Internet access).


### 1.2 Software Requirements

* MCUXpresso IDE version 11.4.x or later to build and debug demo projects. To download, visit the
     [MCUXpresso IDE page](https://www.nxp.com/design/software/development-software/mcuxpresso-software-and-tools-/mcuxpresso-integrated-development-environment-ide:MCUXpresso-IDE).
     (A user account is required to download.)
* SDK version 2.10 for MIMXRT1060-EVKB to get the board configuration for the MCU i.MX RT1060.
    To download, visit the
    [MCUXpresso Software Development Kit (SDK) page](https://www.nxp.com/design/software/development-software/mcuxpresso-software-and-tools-/mcuxpresso-software-development-kit-sdk:MCUXpresso-SDK).
    (A user account is required to download and download with the default option selected.)
    The projects use board support libraries directly from the NXP github repository, however,
    the SDK is required to be able to get the correct board configuration and for the build and
    flash tool to work correctly.
* [Python3](https://www.python.org/downloads/)
    and the Package Installer for Python [pip](https://pip.pypa.io/en/stable/installation/)
    to use the AWS CLI to import certificates and perform OTA Job set up. Pip is included when you install
    from Python 3.10.
* [OpenSSL for Windows](https://www.openssl.org/) to create the OTA signing
    key and certificate. If you have git installed on your machine, you can also use the openssl.exe
    that comes with the git installation.
* [AWS CLI Interface](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
    to import your code-signing certificate, private key, and certificate chain into the AWS Certificate Manager,
    and used for OTA firmware update job set up. Refer to
    [Installing or updating the latest version of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
    for installation instructions. After installation, follow the steps in
    [Configuration basics](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)
    to configure the basic settings (security credentials, the default AWS output format and the default AWS Region)
    that AWS CLI uses to interact with AWS.
* A serial terminal application, such as [Tera Term](https://ttssh2.osdn.jp/index.html.en).


## 2 Hardware and Software Setup

### 2.1 Board Setup

1. Plug in the OM-SE050ARD development kit to the arduino headers on the MIMXRT1060-EVKB board.
     Make sure all the jumpers are in the correct positions as shown in the figure below.

     ![Image](https://user-images.githubusercontent.com/45887168/161103567-f1046d5d-447b-4fc4-ad69-2a81d848b001.png)

1. Connect the USB cable between the personal computer and the open SDA USB port (J1) on the
     board. The serial COM port setting is as below:

     ![Image](https://user-images.githubusercontent.com/45887168/161103634-0855c3b3-cfe4-439e-8e5b-0ce1c0c54b6d.png)

1. Connect the RJ45 cable to the ethernet port.


### 2.2 Importing and Building Projects

1. Open the MCUXpresso IDE and for the "Workspace" choose the location of the root folder where the repository
     was cloned.

     ![Image](https://user-images.githubusercontent.com/45887168/161151822-8be8bc69-60e6-4df3-a065-d4021acae0fc.PNG)

1. Click on "Import...", select "General >> Existing Projects into Workspace" then click "Next".
     A list of all supported projects are shown as below. Click "Finish" to import. This will
     import all projects into the workspace. Alternatively, you can select individual projects
     one at a time.

     ![Image](https://user-images.githubusercontent.com/45887168/161103675-739ae54f-44a9-4d34-96c1-4156973b07dd.png)

     *Note: Make sure to import the SDK 2.10.x for board support configuration.*

     ![Image](https://user-images.githubusercontent.com/45887168/161103646-2cf3fd06-0cca-48b6-beab-62de05864d4e.png)

1. Confirm the MCU and Memory settings under "Project Settings" are correct.

     Bootloader project settings
     ![Image](https://user-images.githubusercontent.com/45887168/161103672-ddafef07-d538-4b63-83c0-02caf5baccd6.png)

     Application project settings
     ![Image](https://user-images.githubusercontent.com/45887168/161103573-4b09ed81-7ed1-4701-95d9-d46d2108d56f.png)

1. Select the project you want to build, right click and then select "Build Project" to build.
     *Note: All projects use MCU libraries under the "core" folder which is submoduled from
     the NXP MCU SDK on github. However, you must install the SDK package to get the correct
     part configuration file for the IDE and you also must install the GUI Flash Tool to
     properly perform build and flash operations. If you get the error message shown below,
     it is because you do not have the required SDK package installed.*

     ![Image](https://user-images.githubusercontent.com/45887168/161103683-c54b2e01-08b9-4dac-96b9-5494fe251045.png)


## 3 Running the Bootloader Project

### 3.1 Create Signing keys for the Bootloader

The project uses the MCUBoot python script called `imgtool.py` to create signing keys,
and sign and verify the image locally. You can use the Command Prompt in Windows or the Terminal
in MAC or Linux machines.

1. Install the necessary requirements for the image tool. From the repo root folder, run:
     ```
     py -m pip install -r Middleware\mcuboot\scripts\requirements.txt
     ```
    ![Image](https://user-images.githubusercontent.com/45887168/161103589-d611a099-d722-4b31-ade8-d06c5667c2a6.png)

1. Create the RSA bootloader signing credentials. Currently, the repository only supports RSA
     signature based validation. From root folder, run the following commands:
     ```
     py Middleware\mcuboot\scripts\imgtool.py keygen -k examples\evkbmimxrt1060\bootloader\signing_key.pem -t rsa-2048
     py Middleware\mcuboot\scripts\imgtool.py getpub -k examples\evkbmimxrt1060\bootloader\signing_key.pem --lang c  > examples\evkbmimxrt1060\bootloader\signing_pub_key.c
     ```
    *Note: Make sure write permission is enabled for this root folder.*
    Confirm that the files `signing_key.pem` and `sign-rsa2048-pub.c` were generated.

    ![Image](https://user-images.githubusercontent.com/45887168/161103575-bbfac181-20cd-4779-ab11-c8984004a8c6.png)
    You will need to use the `signing_key.pem` file created above to sign the application
    image created during the firmware update. The `sign-rsa2048-pub.c` file is used to
    build the MCUBoot bootloader.


### 3.2 Building and Running the Bootloader

1. From the MCUXpresso IDE workspace where the projects were imported, select the "Bootloader" project.

1. Right Click and then select "Build Project".

   ![Image](https://user-images.githubusercontent.com/45887168/161103619-06ea5aba-7ba7-49dc-a36e-2fc18f239a68.png)

1. Click the "GUI Flash Tool" icon, then click "OK". Go to the "Erase" tab, check
     "Mass erase" and then click "Run.." to erase the flash before you program the
     Bootloader image. Wait until "MassErase completed" shows up on the IDE Console.
     *Note: if you previously provisioned the board with the endpoint and thing name,
     this action will erase this configuration information on the flash and will
     require you to provision the board again.*

     ![Image](https://user-images.githubusercontent.com/45887168/161103625-57329b15-eb90-448d-93dc-c2e1be99db69.png)

     ![Image](https://user-images.githubusercontent.com/45887168/161103679-2147a0f4-0f11-44d1-91a3-d513b314da62.png)

     ![Image](https://user-images.githubusercontent.com/45887168/161103628-aa3f3060-93cb-45f0-8025-57665e9ad568.png)

1. Click the blue "Start Debugging" icon to run the Bootloader.

     ![Image](https://user-images.githubusercontent.com/45887168/161103570-e0e197ea-a24c-4e56-b6f5-4e3434f672e8.png)

     The bootloader program is loaded onto the board and stopped at the main function.
     ![Image](https://user-images.githubusercontent.com/45887168/161103676-3edeb28e-8d34-475b-a652-4f1fbfe3145d.png)

1. Click the "Run" icon to start.

     ![Image](https://user-images.githubusercontent.com/45887168/161103648-7a29b989-f788-4297-92bb-ca7669b59dda.png)

     On the serial terminal console, the bootloader start-up message is printed out. The
     bootloader is successfully programmed into the board.
     Notes:
     * Alternatively, you can also use the Flash GUI Tool to program the bootloader
       binary into the flash.
     * Upon boot, the bootloader checks for any image in the primary slot. If there
       is no application image it simply waits in an infinite loop. You can observe the
       message "Unable to find bootable image" on the serial terminal reflecting that status.

     ![Image](https://user-images.githubusercontent.com/45887168/161103600-eea6ffc0-ea9a-48b3-b32d-ec91400f37f9.png)

1. Now you can go ahead and flash the application image to be booted. Refer to the next section,
     "Running Application projects", for details.


## 4 Running Application Projects

### 4.1 Running an Application Project from the Debugger

All application projects are configured to flash the demo to an address known to the bootloader.
To boot a new application image from IDE, we have to jump-start the application from the debugger.

1. Launch the application as normal from the debugger IDE. The debugger goes into an endless
    loop after it flashes the image.

1. Click the "Suspend" icon to pause the debugger.

    ![Image](https://user-images.githubusercontent.com/45887168/161103686-0cc1b3b6-94c3-4274-8bef-9593037f239f.png)

1. Go to the `Debugger Console` in the bottom pane, type `jump ResetISR` to jump to the application
    starting address. The debugger now should jump to the start of main. From here, click the "Resume"
    icon to continue.

    ![Image](https://user-images.githubusercontent.com/45887168/161103602-1ef386da-e072-4ead-a82a-9d00e15f319a.png)


### 4.2 Cloud Setup and Board Provisioning

The project requires a one time setup, both in your AWS account and on the device, to enable
the device to connect to AWS IoT core. These steps include:

* Register a device certificate with AWS IoT Core using your AWS account.
* Create a "thing" in your AWS account and associate it with the device certificate
    and the appropriate device policy.

The project requires a one time device provisioning to be able to connect to AWS IoT Core. For this, you will:

* Provision the MQTT broker endpoint onto the device.
* Provision the "thing" name registered in your account onto the device.

The aws-iot-pubsub project can be used to provision the board. By default, the project boots
into a provision mode at startup where all the configuration options can be set up. The
provisioning mode can be enabled/disabled using the flag `appmainPROVISIONING_MODE`
in the `examples/evkbmimxrt1060/pubsub/app_main.c` file.

Follow the steps below to set up an AWS account and provision the board:

1. Connect to the USB port using a serial terminal. Follow "Starting application project"
     for the "aws-iot-pubsub" project with flag `appmainPROVISIONING_MODE = 1`.
     *Note: the application expects the Ethernet cable to be connected, or else it will enter
     a loop to negotiate the physical connection.*

     ![Image](https://user-images.githubusercontent.com/45887168/161103677-9cb24659-13d9-4043-aedb-a15b13f01d70.png)

     When the application is started correctly, it enters provisioning mode and waits for
     user input commands from a CLI task.

     ![Image](https://user-images.githubusercontent.com/45887168/161103582-12d75027-3d4c-4591-ba72-87978b1e0e0c.png)

1. Run the following command to get the pre-provisioned X.509 certificate from the secure element:
     ```
     pki get cert sss:F0000001
     ```
     `sss:F0000001` is the slot where the certificate is stored in the secure element.

     ![Image](https://user-images.githubusercontent.com/45887168/161142361-68eac8fa-8482-439d-bf90-e602cc5a28cd.png)

1. Copy the PEM certificate from the terminal console. Go to the AWS IoT Console, choose "Secure", choose
     "Certificates", and then choose "Create". Next to "Use my certificate" choose "Get started". On
     "Select a CA" choose "Next". On "Register existing device certificates", choose "Select certificates" and
     select the PEM file you just created. Select "Activate all" then choose "Register certificates".
     For more detailed instructions, see [Register a client certificate signed by an unregistered CA (console)](https://docs.aws.amazon.com/iot/latest/developerguide/manual-cert-registration.html#manual-cert-registration-console-noca).

     ![Image](https://user-images.githubusercontent.com/45887168/161153139-dae3151c-48f3-4d42-a47a-8f839777b425.png)

1. To get the AWS IoT MQTT broker endpoint for your account, go to the AWS IoT console and in the left navigation pane
     choose `Settings`. Copy the endpoint listed under the "Device data endpoint".

     ![Image](https://user-images.githubusercontent.com/45887168/161153141-67c48f02-2c23-4e7f-864b-39bd3f322f30.png)

1. Run the following command to provision the endpoint:
     ```
     conf set mqtt_endpoint <endpoint>
     ```
     Confirm that the application responds "OK".

     ![Image](https://user-images.githubusercontent.com/45887168/161142367-95b95c6e-92ea-4382-8fd2-0bfa9d85aa5a.png)

     (Note: Make sure to wait for the command prompt ">" to type in the command.)

1. In the AWS IoT Core console, create a new thing (using "Skip certificate and create thing") as described in
     [Create AWS IoT resources](https://docs.aws.amazon.com/iot/latest/developerguide/create-iot-resources.html).

1. In the left navigation pane, select "Secure", select "Certificates", and then select the certificate you
     created. Click "Actions >> Attach thing", select the thing you created and then choose "Attach".

1. Go to "Secure >> Policies" and create a device policy like the one below:
     ```
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": "*",
           "Resource": "*"
         }
       ]
     }
     ```
     ***Note**: This policy should only used for development and must not be used for production.*
     Save the policy.

1. Go back to "Security >> Certificates" and select the device certificate you created. Choose
     "Actions >> Attach policy", select the created policy, then choose "Attach" to attach the policy to the
     certificate. Confirm that the thing and policy are attached to the certificate correctly.

     ![Image](https://user-images.githubusercontent.com/45887168/161142365-56a202aa-cba0-44b2-8bf1-17099eb52578.png)

     ![Image](https://user-images.githubusercontent.com/45887168/161142369-778d3a83-9d40-4500-975e-90d78be0cf97.png)

1. Go back to the Serial Terminal console. Provision the new thing name to the device using the following command:
     ```
     conf set thing_name <thing name>
     ```
     Confirm that the application responds "OK".

     ![Image](https://user-images.githubusercontent.com/45887168/161103594-ee026011-1c44-4be0-8c8c-9311bc32ae81.png)

     You have now successfully completed board provisioning.

1. Once the configurations are set up, turn off the provisioning mode by setting
     `appmainPROVISIONING_MODE` to `0`, then recompile and flash the image onto the board.

     ![Image](https://user-images.githubusercontent.com/45887168/161103638-c6c33e06-4a78-4407-be04-082db33b419d.png)


### 4.3 Create a Signed Application Image

All the application images must be signed before they are released as an update, because the
bootloader will verify the application image's signature and only allow a valid, signed image.
They can be signed either via JTAG/SWD or Over-The-Air. To create a signed application image:

1. Build the project to create a new image binary.
1. Sign the new binary image using the MCUBoot key-pair generated as part of setting up the
     bootloader project. From the repository root folder, run the following command:
     ```
     py Middleware\mcuboot\scripts\imgtool.py sign  \
         -k examples\evkbmimxrt1060\bootloader\keys\signing_key.pem --align 4  \
         --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800  \
         --version "MM.mm.bb" projects\evkmimxrt1060\pubsub\Debug\aws_iot_pubsub.bin  \
         aws_iot_pubsub_signed.bin
      ```
     Replace "MM.mm.bb" with the corresponding firmware major version (MM), minor version (mm) and build version (bb).
     This will create a new signed MCUboot image named `aws_iot_pubsub_signed.bin`
     Note: The version of the application image can be found and updated in
     `examples/common/ota/ota_update.c` at the following macros:
     * `APP_VERSION_MAJOR`
     * `APP_VERSION_MINOR`
     * `APP_VERSION_BUILD`


## 5 Running the MQTT Publish/Subscribe Demo

### 5.1 Introduction

This example demonstrates multiple MQTT publish/subscribe tasks running concurrently with an
Over-The-Air firmware update background task. It uses the coreMQTT agent libary to manage
thread safety for the MQTT connection. Each publish/subscribe task runs in a loop to publish
a message to the AWS IoT MQTT broker on a topic, and receive the same message back by
subscribing to the same topic. Topics are constructed per device and per task for this demo. You
can view the number of messages published by each task by logging in to the AWS IoT console and
subscribing to their respective topics. The OTA firmware update task runs an OTA Agent loop which
polls for, and subscribes to, OTA job requests from the AWS IoT OTA service. The OTA agent task
receives firmware chunks and sends control packets over MQTT, concurrently using the coreMQTT
agent task for thread safety.


### 5.2 Runnning the Publish/Subscribe Demo

The board should be successfully provisioned at this time. To turn off provisioning mode, set
`appmainPROVISIONING_MODE` to `0` in `examples/evkbmimxrt1060/pubsub/app_main.c`.
On startup, the demo establishes a TLS connection with the AWS IoT MQTT broker and runs the
publish/subscribe demo tasks using the coreMQTT agent. By default, two pubsub tasks are created.
You can adjust the number of tasks created by setting the config
`appmainMQTT_NUM_PUBSUB_TASKS` in `examples/evkbmimxrt1060/pubsub/app_main.c`
to the desired value. Follow these steps to run the demo:

1. On the serial terminal console, confirm that the TLS handshake was successful and that
     MQTT messages are published.

     ![Image](https://user-images.githubusercontent.com/45887168/161142351-a0cf91a3-153c-4ed6-93a4-924ec257b44b.png)

1. On the IoT console, select "Test" then select "MQTT test client". In the "Subscription topic"
     section, type "#", select "Subscribe to topic", and confirm that the MQTT messages from the
     device are received.

1. To publish a message to the device, go to the "Publish to a topic" section, type
     "/pubsub_demo/<thing_name>/task<task number>" enter a message in the message
     payload section, then select "Publish to a topic".

1. On the serial console, confirm that the device receives the message.
     ![Image](https://user-images.githubusercontent.com/45887168/161103606-9ae8b9ec-f07d-4ff2-ac56-ab4e37284cb9.png)


## 6 Perform Firmware Over-The-Air Updates with AWS IoT

This demo leverages OTA client library and the AWS IoT OTA service for code signing and secure
download of firmware updates. A safe and secure boot process along with root of trust
verification is performed using the open source MCUBoot secondary bootloader. As a pre-requisite,
you should have built and flashed the bootloader project from this repository.

### 6.1 Setup Pre-requisites for OTA Cloud Resources

Before you create an OTA job, the following resources are required:
* An Amazon S3 bucket to store your firmware update.
* An OTA Update service role.
* An OTA user policy.

This is a one time setup required for performing OTA firmware updates. Follow the steps listed
in [OTA update pre-requisites](https://docs.aws.amazon.com/freertos/latest/userguide/ota-prereqs.html)
in the *FreeRTOS User Guide* to set up the required OTA resources:


### 6.2 Create a Code-Signing Certificate

The demos support a code-signing certificate with an ECDSA P-256 key and SHA-256 hash to
perform OTA updates.

1. In your working directory, copy the following text and create a file named `cert_config.txt`. In the
     text, replace `test_signer@amazon.com` with your email address.
     ```
     [ req ]
     prompt             = no
     distinguished_name = my_dn

     [ my_dn ]
     commonName = test_signer@amazon.com

     [ my_exts ]
     keyUsage         = digitalSignature
     extendedKeyUsage = codeSigning
     ```

1. Create an ECDSA code-signing private key.
     ```
     openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt \
         ec_param_enc:named_curve -outform PEM -out ecdsasigner.key
     ```

1. Create an ECDSA code-signing certificate.
     ```
     openssl req -new -x509 -config cert_config.txt -extensions my_exts -nodes \
         -days 365 -key ecdsasigner.key -out ecdsasigner.crt
     ```

1. Import the code-signing certificate, private key, and certificate chain into the AWS
     Certificate Manager.
     ```
     aws acm import-certificate --certificate fileb://ecdsasigner.crt --private-key fileb://ecdsasigner.key
     ```

1. Confirm the ARN for your certificate. You need this ARN when you create an OTA update job.


### 6.3 Provision the Code Signining Public Key to the Board

1. Get the ECDSA public key from the code signing credentials generated in 6.2:
     ```
     openssl ec -in ecdsasigner.key -pubout -outform PEM -out ecdsasigner-pub-key.pem
     ```

1. Confirm that the file `esdsaigner-pub-key.pem` has been created correctly.
     ![Image](https://user-images.githubusercontent.com/45887168/161103614-dd30b4a0-de7c-49d3-8567-a5054a446080.png)

1. Open the target MCUExpressoIDE aws_iot_pubsub project. To switch to device provisioning mode
     set `appmainPROVISIONING_MODE` to `1`, recompile and download the firmware to the board.

1. On the terminal CLI, run the following command:
     ```
     pki set pub_key sss:00223344
     ```

1. The CLI waits for you to input the public key. Copy the PEM public key created in above
     step and paste it to the serial terminal, then press `Enter`. (Note: Paste the
     whole content from "-----BEGIN PUBLIC KEY-----" to "-----END PUBLIC KEY-----".)

1. On successful provisioning, the CLI should print `OK`. At this point, you can
     switch back to device normal mode by turning off the `appmainPROVISIONING_MODE` flag.


### 6.4 Create and Run an OTA Update (AWS IoT console)

To perform an OTA firmware update, you must go through these steps:

* Increment the version of the firmware and create the signed binary image (section 4.3).
* Create an OTA Update Job on the AWS IoT console.
* Restore the original version (lower version number) and run it from the debugger (section 4.1).

After the first successful OTA where a signed binary image is loaded as the primary image, you can perform
subsequent OTA updates without running the last step above using the debugger.

The following steps walk you through OTA job creation and monitoring the OTA process.

1. In the navigation pane of the AWS IoT console, choose **Manage**, and then choose **Jobs**.

1. Choose **Create a job**.

1. Next to **Create a FreeRTOS Over-the-Air (OTA) update job**, choose **Create OTA update job**.

1. You can deploy an OTA update to a single device or a group of devices. Under **Select devices to update**,
     choose **Select**. To update a single device, choose the **Things** tab. To update a group of devices,
     choose the **Thing Groups** tab.

1. If you are updating a single device, select the check box next to the IoT thing associated with your device.
     If you are updating a group of devices, select the check box next to the thing group associated with your
     devices. Choose **Next**.

1. Under **Select the protocol for firmware image transfer**, choose **MQTT**, or choose both **MQTT** and
     **HTTP** to allow each device to determine the protocol it will use.

1. Under **Select and sign your file**, choose **Sign a new file for me**.

1. Under **Code signing profile**, choose **Create**.

1. In **Create a code signing profile:**
     1. Type in a name for this profile.
     1. For the **Device hardware platform**, select: "Windows Simulator".
     1. Under **Code signing certificate**, choose "Select", then choose the
          certificate that you created with AWS CLI earlier.
     1. Under "Path name of code signing certificate on device", enter "sss:00223344".
          This is the slot address of the secure element where the key for the code signing
          certificate is stored.
     1. Click "Create". Confirm that the code signing profile was created successfully.
     Note: Currently the slot id is hardcoded in the code. If you want to change to a different slot, you can update it.

1. Back on the FreeRTOS OTA Job console:
     1. Under "Code signing profile", select the code signing profile that was just created
          from the drop down list.
     1. Under "File", choose "Upload a new file" then click "Choose file". A file browser
          pops up. Select the signed binary image (`aws_iot_pubsub_signed.bin`).
          Note: the version of the new image must be later than the current image on the
          board or else OTA will not proceed.
     1. Under "File upload location in S3", click "Browse S3", then select the S3 bucket
          that you created for this job.
     1. Under "Path name of file on device", type "NA"
     1. Under "IAM role for OTA update job", choose the role that you created earlier for the OTA update from the
          drop down list.

          ![Image](https://user-images.githubusercontent.com/45887168/161103579-5359e546-7a34-4e7c-a1b5-e69b55471a23.png)

          Then, click "Next" to create OTA job. Confirm if the Job was created successfully.
          Note: If it fails to create an OTA job, make sure the role for this OTA job update has the correct
          permissions (policies) attached.
          Below is the list of managed policies used and custom policies defined for the account ID, role and S3
          bucket resource.

          ![Image](https://user-images.githubusercontent.com/45887168/161103610-743a6067-7729-4cc8-8dcb-d18f3ebb4f1e.png)

          GetSetRolePolicy:
          ```
          {
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Effect": "Allow",
                      "Action": [
                          "iam:GetRole",
                          "iam:PassRole"
                      ],
                      "Resource": "arn:aws:iam::<account ID>:role/<role name>"
                  }
              ]
          }
          ```
          NXP-FreeRTOS-OTA-Policy:
          ```
          {
              "Version": "2012-10-17",
              "Statement": [
              {
                 "Effect": "Allow",
                 "Action": [
                     "s3:GetObjectVersion",
                     "s3:PutObject",
                     "s3:GetObject"
                 ],
                 "Resource": "arn:aws:s3:::<S3 bucket name>*"
              },
              {
                 "Effect": "Allow",
                 "Action": [
                     "signer:StartSigningJob",
                     "signer:DescribeSigningJob",
                     "signer:GetSigningProfile",
                     "signer:PutSigningProfile"
                 ],
                 "Resource": "*"
              },
              {
                 "Effect": "Allow",
                 "Action": [
                     "s3:ListBucketVersions",
                     "s3:ListBucket",
                     "s3:ListAllMyBuckets",
                     "s3:GetBucketLocation"
                 ],
                 "Resource": "*"
              },
              {
                 "Effect": "Allow",
                 "Action": [
                     "iot:DeleteJob",
                     "iot:DescribeJob"
                 ],
                 "Resource": "arn:aws:iot:*:*:job/AFR_OTA*"
              },
              {
                 "Effect": "Allow",
                 "Action": [
                     "iot:DeleteStream"
                 ],
                 "Resource": "arn:aws:iot:*:*:stream/AFR_OTA*"
              },
              {
                 "Effect": "Allow",
                 "Action": [
                     "iot:CreateStream",
                     "iot:CreateJob"
                 ],
                 "Resource": "*"
              }
              ]
          }
          ```

1. Once the job is created successfully, the demo should start downloading the firmware chunks.
     The process can be monitored using logs from the console. Note: make sure the device is
     running with the older version of the application image.

1. Once all the firmware image chunks are downloaded and the signature is validated, the demo
     resets by itself. The MCUBoot loader verifies the new image using the signing public key
     created as part of bootloader project. Once the image is verified, the bootloader swaps the
     image and boots up with the new image. On booting up, the new image verifies the image
     version with AWS IoT and marks the job as completed successfully.

1. On the device side, check that the device reboots, and the bootloader verifies, swaps, then
     erases the new image in the secondary slot and jumps to the application. Verify the version
     of the new application.

     ![Image](https://user-images.githubusercontent.com/45887168/161142357-18afd557-6f79-451a-8d04-5614b932db95.png)

1. Verify that the bootloader updates the primary and secondary slots correctly and jumps to the
     application correctly.

     ![Image](https://user-images.githubusercontent.com/45887168/161142363-9bdae63b-8f0e-4cfd-8e4e-424f823226b2.png)

1. On the AWS IoT console, confirm that the "Status" of the OTA job is "Completed".

     ![Image](https://user-images.githubusercontent.com/45887168/161142364-e4ed3234-2b0c-465e-9426-eaa8f3e39cfc.png)


## 7 Running the Shadow Demo

1. From the MCUXpressoIDE workspace where the aws_iot_shadow project was imported, do the following:
    1. Set `appmainPROVISIONING_MODE` in `app_main.c` to 0.
    2. Set `appmainINCLUDE_OTA_UPDATE_TASK` in `app_main.c` to 1.
    3. If you update the shadow firmware into device via OTA, pump version up in `ota_update.c`.
1. Build and sign the binary image. See section 4.3 "Create a Signed Application Image".
1. Update this new firmware using OTA. See section 6 "Perform Firmware Over-The-Air Updates with AWS IoT".
    1. Or you can run from the debugger. See section 4.1 "Running an Application Project from the Debugger".
1. On AWS IoT console, Select "Manage >> Things", click on the thing you created to represent this device,
     then select "Device Shadows >> Classic Shadow".

You should see the device shadow state "powerOn" toggled every few minutes. To update this state, click the
  "Edit" button, and update the "powerOn" value. You should see the device sync with the updated state.
```
{
     "state": {
          "desired": {
               "powerOn": 1
          },
          "reported": {
               "powerOn": 1
          }
     }
}
```
Device Shadow metadata
```
{
     "metadata": {
          "desired": {
               "powerOn": {
                    "timestamp": 1648692896
               }
          },
          "reported": {
               "powerOn": {
                    "timestamp": 1648692896
               }
          }
     }
}
```


## 8 Running the Defender Demo

1. From the MCUXpressoIDE workspace where aws_iot_defender project was imported:
    1. Set `appmainPROVISIONING_MODE` in `app_main.c` to 0.
    2. Set `appmainINCLUDE_OTA_UPDATE_TASK` in `app_main.c` to 1.
    3. If you update the shadow firmware on the device via OTA, increment the version in `ota_update.c`.
2. Build and sign the binary image. See section 4.3 "Create a Signed Application Image".
3. Update this new firmware using OTA. See section 6 "Perform Firmware Over-The-Air Updates with AWS IoT".
    1. Or you can run from the debugger. See section 4.1 "Running an Application Project from the Debugger".
4. On the AWS IoT console, Select "Manage >> Things", click on the thing you created to represent this device, then
     select "Defender metrics". Select the Metric you want to see from the drop down menu. Supported metrics are:
    * Bytes in
    * Bytes out
    * Packets in
    * Packets out

Note: At power up, the device will wait for a few minutes before it starts sending the metrics.
On device side, you can observe it publishing messages to the device defender topic.

Besides the Defender metrics graph on the console, you can also use the MQTT Client Test and subscribe to the defender topic to receive the message.
    * Topic: `$aws/things/<Thing Name>/defender/metrics/cbor`.

![Image](https://user-images.githubusercontent.com/45887168/161165986-202efeaf-5d21-44e2-ac26-a131467552eb.png)


## 9 Troubleshooting Guide

1. The device can not do an OTA update again after failing the first OTA running with the debugger.
     >When running with the debugger, the image was not signed. If the first OTA fails, the bootloader will try to recover by loading the prior good image and this will fail as the image loaded by debugger is not signed. The bootloader will update memory status as bad (“magic=bad”. Both Primary and Secondary image status should be either “good” or “unset”. If you see the state as “bad”, you will need to use Flash GUI tool and perform “mass erase” for the bootloader to recover.

1. The OTA job status is Completed but Failed.
     >Please check device log for specific reason as why it fails. Some conditions can be:
     > * The version of the new image is not higher than the current one. Recreate the signed binary with a higher version.
     > * The image is not signed with a valid signature. Recreate the signed binary with a correct signature.
     > * The device encounters a niche error condition, such as receiving duplicate blocks, or the OTA buffer is
       not available to handle these error conditions. In these instances, you can retry OTA job from the console.

