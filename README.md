# FieldEdge Packet Capture Utility

A Python library for creating and analyzing Wireshark packet captures
based on [**`pyshark`**](https://github.com/KimiNewt/pyshark).

[Documentation](https://inmarsat-enterprise.github.io/fieldedge-pcap/)

This package requires [**tshark**](https://www.wireshark.org/docs/man-pages/tshark.html)
to be installed on the host system.

## Usage

### Create a Packet Capture file

Using **`fieldedge_pcap.pyshark.create_pcap`**:

A subdirectory is created in the `target_directory`. If none is specified it
stores to the user's home directory.
The subdirectory created is named `/capture_YYYYmmdd`.
The default filename is `capture_YYYYmmddTHHMMSS_D_i.pcap` where `D` is the
duration in seconds and `i` is the interface name. Filename may be overridden
if provided as an argument.

To run in the background use a `multiprocessing` `Process` and `Queue`:

```
import multiprocessing

q = multiprocessing.Queue()
kwargs = {
    'interface': 'eth1',
    'duration': 600,
    'queue': q,
}
capture_process = multiprocessing.Process(target=create_pcap,
                                          name='packet_capture',
                                          kwargs=kwargs)
capture_process.start()
capture_process.join()
capture_file = q.get()
```

Often times the packet capture process will result in a corrupted file or
have duplicate packets.
To check for corruption run `tshark -r <capture_file>` which will have a
returncode 2 if corrupt, and stderr will include
`appears to have been cut short`.
To fix a corrupted file run `editcap <capture_file> <capture_file>` which
should have a returncode `0`.

### Process a Packet Capture file

Using **`fieldedge_pcap.pyshark.process_pcap`**:

To run in the background use a `multiprocessing` `Process` and `Queue`, and
`queue.Empty` exception for timeouts:

```
import multiprocessing
import queue

q = multiprocessing.Queue()
kwargs = {
    'filename': filename,
    'display_filter': display_filter,
    'queue': q,
}
process = multiprocessing.Process(target=process_pcap,
                                    name='packet_capture',
                                    kwargs=kwargs)
process.start()
while process.is_alive():
    try:
        while True:
            packet_statistics = q.get(block=False)
    except queue.Empty:
        pass
process.join()
```

### Get Analysis data

After a file has been processed to produce a `PacketStatistics` object, a
typical operation is to generate simple data series based on
procotol/application use, to display or graph.

```
data_series = packet_statistics.data_series_application_size()
for application, series in data_series.items():
    print(f'Application: {application}')
    for tup in series:
        print(f'Timestamp: {tup[0]} | Bytes: {tup[1]}')
```

Conversation summaries is also a typical use:

```
import json
...

convo_analysis = packet_statistics.analyze_conversations()
for hosts, detail in convo_analysis.items():
    print(f'Conversation {hosts}:\n{json.dumps(detail, indent=2)}')
```
Would return something like:
```
Conversation ('0.0.0.0', '255.255.255.255'):
{
  "count": 1,
  "applications": [
    "UDP_DHCP_RESPONSE"
  ],
  "start_times": [
    1642667840.985
  ],
  "packet_intervals": {
    "AB_intervals": {
      "UDP_DHCP_RESPONSE_382B": 12.383,
      "UDP_DHCP_RESPONSE_389B": null
    },
    "BA_intervals": {}
  },
  "bytes": 2681,
  "bad_packet_count": 0,
  "bytes_bad": 0,
  "retransmit_count": 0,
  "retransmit_bytes": 0,
  "repeat_mean": null,
  "repeat_stdev": null
}
```
