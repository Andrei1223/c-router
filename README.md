# Router Implementation

A C-based implementation of a router's dataplane. This project handles packet forwarding,
routing using an efficient Longest Prefix Match (LPM) via a Trie data structure and dynamic address resolution using the ARP protocol.

### Features

* **IPv4 Forwarding**: Validates checksums, handles TTL decrementing, and updates L2 addresses.
* **Efficient LPM**: Route table lookups optimized with a Trie.
* **ARP Protocol**: Dynamic MAC address discovery with request/reply handling and packet queuing.
* **ICMP Support**: Generates *Echo Reply*, *Destination Unreachable*, and *Time Exceeded* messages.

### Build

Run the following command to compile the project:

```
make

```

### Cleanup

To remove compiled binaries and object files:

```
make clean

```
