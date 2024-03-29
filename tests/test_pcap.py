import logging
import json
import os
import queue
import shutil
import subprocess
from multiprocessing import Process, Queue
from time import time

from fieldedge_pcap import pyshark

TEST_DIR = './pcaps/samples'
TEST_INTERFACE = 'en0'

_log = logging.getLogger(__name__)


def is_corrupt(filename: str) -> bool:
    try:
        res = subprocess.run(['tshark', '-r', f'{filename}'], check=True,
            capture_output=True, text=True).stderr
    except subprocess.CalledProcessError as err:
        res = err.stderr
    if 'appears to have been cut short' in res:
        return True
    return False


def fix_corrupt(filename: str) -> bool:
    oldname = f'{filename}.orig'
    os.rename(filename, oldname)
    try:
        # Observation is that running editcap with same source and dest
        #   filename causes problems truncating the file.
        res = subprocess.run(['editcap', f'{oldname}', f'{filename}'],
            check=True, capture_output=True, text=True).returncode
    except subprocess.CalledProcessError as err:
        res = err.returncode
    if res == 0:
        return True
    return False


def cleanup(filename: str):
    shutil.rmtree(os.path.dirname(filename))


def test_create():
    """Creates and reads a pcap file on a local interface."""
    delete_file = False
    duration = 10
    capture_filter = 'not (arp or udp port 1900 or udp port 5353)'
    filename = pyshark.create_pcap(interface=TEST_INTERFACE,
                                duration=duration,
                                target_directory=TEST_DIR,
                                debug=True,
                                bpf_filter=capture_filter,
                                )
    assert(os.path.isfile(filename))
    if delete_file:
        cleanup(filename)


def test_create_multiprocessing():
    queue = Queue()
    kwargs = {
        'interface': TEST_INTERFACE,
        'duration': 10,
        'target_directory': TEST_DIR,
        'queue': queue,
        'debug': True,
        'bpf_filter': None,
        'use_ek': True,
    }
    process = Process(target=pyshark.create_pcap, kwargs=kwargs)
    process.start()
    process.join()
    filename = queue.get()
    assert(os.path.isfile(filename))
    if is_corrupt(filename):
        assert fix_corrupt(filename)
    # cleanup(filename)


def test_create_and_read_pcap():
    """Creates and reads a pcap file on a local interface."""
    filename = pyshark.create_pcap(interface=TEST_INTERFACE, duration=5,
        target_directory=TEST_DIR, debug=True)
    assert(os.path.isfile(filename))
    if is_corrupt(filename):
        assert fix_corrupt(filename)
    packet_statistics = pyshark.process_pcap(filename=filename)
    assert(isinstance(packet_statistics, pyshark.PacketStatistics))
    cleanup(filename)


def test_packet_statistics():
    """Validates content of the PacketStatistics object."""
    filename = f'{TEST_DIR}/mqtts_sample.pcap'
    duration = 50
    # filename = f'{TEST_DIR}/capture_20211210T173939_1800.pcap'
    # duration = 1800
    packet_stats = pyshark.process_pcap(filename=filename)
    assert isinstance(packet_stats, pyshark.PacketStatistics)
    assert isinstance(packet_stats.duration, int)
    assert packet_stats.duration == duration
    assert packet_stats.packet_count > 0
    assert packet_stats.bytes_total > 0
    for conversation in packet_stats.conversations:
        assert isinstance(conversation, pyshark.Conversation)
        for simple_packet in conversation.packets:
            assert isinstance(simple_packet, pyshark.SimplePacket)
            assert isinstance(simple_packet.a_b, bool)
            assert isinstance(simple_packet.application, str)
            assert isinstance(simple_packet.highest_layer, str)
            assert isinstance(simple_packet.timestamp, float)
            assert isinstance(simple_packet.size, int)
            assert isinstance(simple_packet.src, str)
            assert isinstance(simple_packet.dst, str)
            assert isinstance(simple_packet.srcport, int)
            assert isinstance(simple_packet.dstport, int)
        grouped = conversation.group_packets_by_size()
        assert isinstance(grouped, tuple)
        assert len(grouped) == 2
        for direction in grouped:
            assert isinstance(direction, dict)
            for key in direction:
                assert isinstance(direction[key], list)
    dataset = packet_stats.data_series_application_size()
    assert isinstance(dataset, dict)
    for key in dataset:
        assert isinstance(dataset[key], list)
        for datapoint in dataset[key]:
            assert isinstance(datapoint, tuple)
            assert isinstance(datapoint[0], float)
            assert isinstance(datapoint[1], int)


def test_process_multiprocessing():
    """Processes a pcap separately using multiprocessing."""
    # filename = f'{TEST_DIR}/mqtts_sample.pcap'
    # filename = f'{TEST_DIR}/capture_20211205T142537_60.pcap'
    filename = f'{TEST_DIR}/capture_20211215T031635_3600.pcap'
    q = Queue()
    process = Process(target=pyshark.process_pcap, args=(filename, None, q))
    starttime = time()
    process.start()
    while process.is_alive():
        try:
            while True:
                packet_stats = q.get(block=False)
        except queue.Empty:
            pass
    process.join()
    processing_time = time() - starttime
    assert isinstance(packet_stats, pyshark.PacketStatistics)
    data_dict = packet_stats.data_series_application_size()
    assert isinstance(data_dict, dict)


def test_process():
    """Processes a pcap."""
    # filename = '../pcaps/samples/mqtts_sample.pcap'
    filename = f'{TEST_DIR}/capture_20211215T031635_3600.pcap'
    if is_corrupt(filename):
        assert fix_corrupt(filename)
    starttime = time()
    packet_stats = pyshark.process_pcap(filename=filename)
    processing_time = time() - starttime
    assert isinstance(packet_stats, pyshark.PacketStatistics)


def test_unique_hosts():
    filename = f'{TEST_DIR}/capture_20211215T031635_3600.pcap'
    packet_stats = pyshark.process_pcap(filename=filename)
    unique_hosts = packet_stats.unique_host_pairs()
    temp = []
    for hostpair in unique_hosts:
        assert hostpair not in temp
        temp.append(hostpair)


def test_analyze_conversations():
    # filename = f'{TEST_DIR}/capture_20220303T021914_60_eth0.pcap'
    # filename = f'{TEST_DIR}/capture_20211215T031635_3600.pcap'
    filename = f'{TEST_DIR}/capture_20220119T000001_60.pcap'
    packet_stats = pyshark.process_pcap(filename=filename)
    analysis = packet_stats.analyze_conversations()
    for name, detail in analysis.items():
        _log.debug(f'Conversation {name}:\n{json.dumps(detail, indent=2)}')
    assert isinstance(analysis, dict) and len(analysis) > 0
    for hostpair, summary in analysis.items():
        assert isinstance(summary, dict)
        assert summary['count'] > 0
        assert len(summary['applications']) > 0
        assert len(summary['start_times']) == summary['count']
        assert 'packet_intervals' in summary
        assert 'repeat_mean' in summary
        assert 'repeat_stdev' in summary
        assert 'bad_packet_count' in summary


def test_data_series_application_size():
    filename = f'{TEST_DIR}/valmont/valmont-mar17-2022.pcap'
    packet_stats = pyshark.process_pcap(filename=filename)
    data_series = packet_stats.data_series_application_size()
    for app, data in data_series.items():
        assert isinstance(app, str)
        for d in data:
            assert d is not None
