from enum import Enum


class EthernetProtocol(Enum):
    """Mappings for Ethernet packet types."""
    ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
    ETH_TYPE_PUP = 0x0200  # PUP protocol
    ETH_TYPE_IP = 0x0800  # IP protocol
    ETH_TYPE_ARP = 0x0806  # address resolution protocol
    ETH_TYPE_AOE = 0x88a2  # AoE protocol
    ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
    ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
    ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
    ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
    ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
    ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
    ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
    ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
    ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
    ETH_TYPE_PPP = 0x880B  # PPP
    ETH_TYPE_MPLS = 0x8847  # MPLS
    ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
    ETH_TYPE_PPPOE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
    ETH_TYPE_PPPOE = 0x8864  # PPP Over Ethernet Session Stage
    ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
    ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging


class KnownTcpPorts(Enum):
    """Mappings for common registered/known application layer TCP ports."""
    SMTP = 25
    HTTP = 80
    HTTP_TLS = 443
    DNS = 53
    FTP = 20
    FTPC = 21
    TELNET = 23
    IMAP = 143
    RDP = 3389
    SSH = 22
    HTTP2 = 8080
    MODBUS = 502
    MODBUS_TLS = 802
    MQTT = 1883
    MQTT_TLS = 8883
    MQTT_SOCKET = 9001
    DOCKERAPI = 2375
    DOCKERAPI_TLS = 2376
    SRCP = 4303
    COAP = 5683
    COAP_TLS = 5684
    DNP2 = 19999
    DNP = 20000
    IEC60870 = 2404


class KnownUdpPorts(Enum):
    """Mappings for common registered/known application layer TCP ports."""
    SNMP = 161
    DNS = 53
    DHCP_QUERY = 67
    DHCP_RESPONSE = 68
    NTP = 123
