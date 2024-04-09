# Low-Level DNS Client-Server Implementation in C

This code base provides a low-level DNS client-server implementation in C, utilizing raw sockets at the IP level. This allows for a deeper understanding of the DNS protocol and networking concepts.

## Prerequisites

- The code is written in C and requires a C compiler (e.g., GCC).
- The make utility is required to build the executables.

## Building

To build the executables, run the following command:

```
make
```

or 

```
make build
```

## Running the DNS Server

To run the DNS server, execute the following command:

```
sudo ./server
```

The server program requires superuser privileges due to the usage of raw sockets.

## Running the DNS Client

To run the DNS client, execute the following command:

```
sudo ./client
```

Similar to the server, the client program requires superuser privileges for raw socket access.

## Notes

- Ensure that superuser privileges are granted for running both the server and client programs.
- This implementation offers a foundational understanding of DNS and networking, utilizing raw sockets at the IP level.
- Customization and extension of functionality can be achieved by modifying the source code according to specific requirements.

## Disclaimer

Usage of raw sockets and superuser privileges requires caution, as it bypasses certain network protections and can potentially pose security risks. Ensure that the code is used responsibly and only in controlled environments.
