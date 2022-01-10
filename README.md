# FieldEdge Packet Capture Utility

A Python library for creating and analyzing Wireshark packet captures.

[Documentation](https://inmarsat-enterprise.github.io/fieldedge-pcap/)

This package requires [**tshark**](https://www.wireshark.org/docs/man-pages/tshark.html)
to be installed on the host system.

## Docker

In order to simplify packaging and distribution for use with Inmarsat's
**FieldEdge** tools, a Docker image has been created targeting use on a
`armv7` processor such as Raspberry Pi 3B+, 4 or Zero 2 W.  To use in a
Dockerfile add the following line:
```
FROM inmarsat/fieldedge-pyshark:latest
...
```
