#!/usr/bin/python

import hashlib
import pcapy
import sys

from impacket import ImpactDecoder, ImpactPacket
from lxml import etree

def main(argv):
    try:
        try:
            read_pcap(argv[1])
        except pcapy.PcapError as e:
            print e

        print("Done\n")
    except IndexError as e:
        print e.message
        print "Usage : python pcap_port_splitter.py <labelled filename>"


def parse_packet(dumper, ports, header, packet):
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(packet)

    #print str(ether.get_ether_type()) + " " + str(ImpactPacket.IP.ethertype)

    if ether.get_ether_type() == ImpactPacket.IP.ethertype:
        iphdr = ether.child()
        transporthdr = iphdr.child()

        if isinstance(transporthdr, ImpactPacket.TCP):
            d_port = transporthdr.get_th_dport()
        elif isinstance(transporthdr, ImpactPacket.UDP):
            d_port = transporthdr.get_uh_dport()
        else:
            return

        if d_port not in ports:
            return

        dumper[d_port].dump(header, packet)


def read_pcap(filename):
    ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445]
    dataset_dir = "/home/baskoro/Documents/Doctoral/Research/previousImplementation/McPAD/RootDirectory/pcap/"

    cap = pcapy.open_offline(dataset_dir + filename)
    dumper = {}
    for port in ports:
        dumper[port] = cap.dump_open(dataset_dir + str(port) + "-" + filename)

    while(1):
        (header, packet) = cap.next()
        if not header:
            break
        parse_packet(dumper, ports, header, packet)


if __name__ == '__main__':
	main(sys.argv)