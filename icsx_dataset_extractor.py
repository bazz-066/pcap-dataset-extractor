#!/usr/bin/python

import hashlib
import pcapy
import sys

from impacket import ImpactDecoder, ImpactPacket
from lxml import etree

def main(argv):
    try:
        data_date = argv[1]
        filename = data_date[data_date.index("Testbed"):len(data_date) - 4]

        date_to_filename = {'TestbedSatJun12Flows': '12jun',
                            'TestbedSunJun13Flows': '13jun',
                            'TestbedMonJun14Flows': '14jun',
                            'TestbedTueJun15-1Flows': '15jun',
                            'TestbedTueJun15-2Flows': '15jun',
                            'TestbedTueJun15-3Flows': '15jun',
                            'TestbedWedJun16-1Flows': '16jun',
                            'TestbedWedJun16-2Flows': '16jun',
                            'TestbedWedJun16-3Flows': '16jun',
                            'TestbedThuJun17-1Flows': '17jun',
                            'TestbedThuJun17-2Flows': '17jun',
                            'TestbedThuJun17-3Flows': '17jun',
                            }
        dataset_dir = "/home/baskoro/Documents/Dataset/ICSX 2012/"

        flabels = open(dataset_dir + "csv/" + date_to_filename[filename] + ".csv", "w")
        labels = {}
        fdataset = etree.parse(argv[1])
        root = fdataset.getroot()

        for record in root.getchildren():
            parsed = {}
            parsed["src_address"] = record.find("source").text
            parsed["dst_address"] = record.find("destination").text
            parsed["src_port"] = record.find("sourcePort").text
            parsed["dst_port"] = record.find("destinationPort").text
            parsed["protocol"] = record.find("protocolName").text
            parsed["label"] = record.find("Tag").text

            save_label(labels, parsed)
            #bpf_src = "src host " + parsed["src_address"]
            #bpf_dst = "dst host " + parsed["dst_address"]
            #bpf_src_port = "src port " + parsed["src_port"]
            #bpf_dst_port = "dst port " + parsed["dst_port"]

        print("Labels are stored, reading pcap files...\n")
        try:
            read_pcap(argv[1], flabels, labels)
        except pcapy.PcapError as e:
            print e

        flabels.close()
        print("Done\n")
    except IndexError as e:
        print "Usage : python icsx_dataset_extractor.py <labelled filename>"


def save_label(labels, parsed):
    id = "{}-{}-{}-{}-{}".format(parsed["src_address"], parsed["src_port"], parsed["dst_address"], parsed["dst_port"], parsed["protocol"])
    id_rev = "{}-{}-{}-{}-{}".format(parsed["dst_address"], parsed["dst_port"], parsed["src_address"], parsed["src_port"], parsed["protocol"])
    labels[id] = parsed["label"]
    labels[id_rev] = parsed["label"]


def parse_packet(flabels, labels, header, packet):
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(packet)

    #print str(ether.get_ether_type()) + " " + str(ImpactPacket.IP.ethertype)

    if ether.get_ether_type() == ImpactPacket.IP.ethertype:
        iphdr = ether.child()
        transporthdr = iphdr.child()

        s_addr = iphdr.get_ip_src()
        d_addr = iphdr.get_ip_dst()

        if isinstance(transporthdr, ImpactPacket.TCP):
            s_port = transporthdr.get_th_sport()
            d_port = transporthdr.get_th_dport()
            seq_num = transporthdr.get_th_seq()
            d_length = len(transporthdr.get_data_as_string())
            protocol = "tcp_ip"
        elif isinstance(transporthdr, ImpactPacket.UDP):
            s_port = transporthdr.get_uh_sport()
            d_port = transporthdr.get_uh_dport()
            seq_num = 0
            d_length = transporthdr.get_uh_ulen()
            protocol = "udp_ip"
        else:
            s_port = 0
            d_port = 0
            seq_num = 0
            d_length = -1
            protocol = "unknown"

        if d_length == 0:
            return

        id = "{}-{}-{}-{}-{}".format(s_addr, s_port, d_addr, d_port, protocol)

        if labels.has_key(id):
            flabels.write("{},{},{},{},{},{},{},{}\n".format(s_addr, s_port, d_addr, d_port, protocol, seq_num, d_length, labels[id]))
        else:
            flabels.write("{},{},{},{},{},{},{},{}\n".format(s_addr, s_port, d_addr, d_port, protocol, seq_num, d_length, "Normal-0"))
            #print "{} not found\n".format(id)
            #raise Exception("id not found")


def read_pcap(data_date, flabels, labels):
    filename = data_date[data_date.index("Testbed"):len(data_date)-4]

    date_to_filename = {'TestbedSatJun12Flows' : '12jun',
                        'TestbedSunJun13Flows' : '13jun',
                        'TestbedMonJun14Flows' : '14jun',
                        'TestbedTueJun15-1Flows': '15jun',
                        'TestbedTueJun15-2Flows': '15jun',
                        'TestbedTueJun15-3Flows': '15jun',
                        'TestbedWedJun16-1Flows': '16jun',
                        'TestbedWedJun16-2Flows': '16jun',
                        'TestbedWedJun16-3Flows': '16jun',
                        'TestbedThuJun17-1Flows' : '17jun',
                        'TestbedThuJun17-2Flows' : '17jun',
                        'TestbedThuJun17-3Flows' : '17jun',
                        }
    dataset_dir = "/home/baskoro/Documents/Dataset/ICSX 2012/"

    cap = pcapy.open_offline(dataset_dir + "testbed-" + date_to_filename[filename] + ".pcap")

    while(1):
        (header, packet) = cap.next()
        if not header:
            break
        parse_packet(flabels, labels, header, packet)


if __name__ == '__main__':
	main(sys.argv)