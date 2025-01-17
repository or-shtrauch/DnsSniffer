# DnsSniffer

DnsSniffer is a powerful tool for capturing and analyzing DNS traffic. It leverages various libraries to provide detailed insights into DNS queries and responses.

## Features
- Capture DNS traffic in real-time
- Analyze DNS queries and responses
- Support for multiple protocols
- Integrates with iptables in userspace and kernel
- Requires nflog dependency in the kernel
- Easy to integrate with other tools

## Dependencies

This project uses the following submodules:

- [libnetfilter_log](https://git.netfilter.org/libnetfilter_log)
- [libnfnetlink](https://git.netfilter.org/libnfnetlink)
- [libmnl](https://git.netfilter.org/libmnl)

## Installation

To install DnsSniffer, follow these steps:

1. Clone the repository:
    ```sh
    git clone --recursive https://github.com/ororor2000/DnsSniffer.git
    cd DnsSniffer
    ```

2. Install dependencies:
    ```sh
    sudo apt-get update
    sudo apt-get install -y cmake gcc
    ```

3. Build the project:
    ```sh
    mkdir -p build
    cd build
    cmake ..
    make
    ```

## Usage

To run DnsSniffer, execute the following command:
```sh
./build/DnsSniffer