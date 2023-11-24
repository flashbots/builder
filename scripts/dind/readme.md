# Emulate Network Using Docker-in-Docker (DinD)

This documentation details the use of Docker-in-Docker (DinD) to emulate network environments for testing builder performance. This method provides an isolated environment, removing the need for Go or Kurtosis installations on the host system.

## Introduction

Utilizing a DinD setup allows developers to create a contained environment where Docker images can be built and Kurtosis enclaves can be managed. This is particularly useful for simulating network conditions in a clean state without affecting the host's setup.

## Running in a DinD Environment

### Prerequisites

- **Docker**: Ensure Docker is installed and running on your system. The DinD process will be running as a Docker container.

### Setup and Execution

1. **Create the DinD Environment**:
    - Run a DinD container for an isolated build environment named `builder-dind-container` assuming you are currently in this folder:
      ```shell
      docker build -f ./Dockerfile.kurtosis_dind -t builder-dind-image ../../
      docker run -dit --privileged --name builder-dind-container builder-dind-image
      ```
      ***note:*** privileged mode that is not needed when using local hosting in your docker described [here](../)

2. **Build the Builder Image**:
    - Execute the build command within the DinD environment:
      ```shell
      docker exec builder-dind-container go run emulate_network.go build -t=custom-builder-tag
      ```

3. **Start the Enclave**:
    - Start an enclave with the specified builder image:
      ```shell
      docker exec builder-dind-container go run emulate_network.go run -n=builder-enclave -t=custom-builder-tag
      ```

4. **Stop the Enclave**:
    - To stop a running enclave, use the following command:
      ```shell
      docker exec builder-dind-container go run emulate_network.go stop -n=builder-enclave
      ```

5. **Cleanup**:
    - To stop and remove the DinD container, execute:
      ```shell
      docker stop builder-dind-container 
      docker rm builder-dind-container
      ```

**Note**: Replace `builder-dind-container` with a descriptive name relevant to your project, and `builder-dind-image` with the image name you've prepared for the DinD environment. The `custom-builder-tag` should be replaced with the actual tag name you wish to assign to your builder image.

## Known Issues and Solutions
Ports control is missing in ethereum-package.

By following these instructions, developers can leverage a Docker-in-Docker approach to emulate networks and test builder performance in a controlled and isolated manner.