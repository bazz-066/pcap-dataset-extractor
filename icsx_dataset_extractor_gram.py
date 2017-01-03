#!/usr/bin/python

import hashlib
import pcapy
import sys

from collections import Counter
from impacket import ImpactDecoder, ImpactPacket
from lxml import etree

def main(argv):
    try:
        data_date = argv[1]
        dataset_dir = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"

        if data_date != "11jun":
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

            flabels = open(dataset_dir + "csv-bytefreq/" + date_to_filename[filename] + ".csv", "w")
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
                if record.find("Tag").text == "Attack":
                    parsed["label"] = 1
                else:
                    parsed["label"] = 0

                save_label(labels, parsed)
                #bpf_src = "src host " + parsed["src_address"]
                #bpf_dst = "dst host " + parsed["dst_address"]
                #bpf_src_port = "src port " + parsed["src_port"]
                #bpf_dst_port = "dst port " + parsed["dst_port"]

            print("Labels are stored, reading pcap files...\n")
        else:
            flabels = open(dataset_dir + "csv-bytefreq/11jun.csv", "w")
            labels = {}

        try:
            read_pcap(argv[1], flabels, labels)
        except pcapy.PcapError as e:
            print e

        flabels.close()
        print("Done\n")
    except IndexError as e:
        print "Usage : python icsx_dataset_extractor_gram.py <labelled filename>"


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
            v_protocol = "1,0"
        elif isinstance(transporthdr, ImpactPacket.UDP):
            s_port = transporthdr.get_uh_sport()
            d_port = transporthdr.get_uh_dport()
            seq_num = 0
            d_length = transporthdr.get_uh_ulen()
            protocol = "udp_ip"
            v_protocol = "0,1"
        elif isinstance(transporthdr, ImpactPacket.ICMP):
            s_port = 0
            d_port = 0
            seq_num = 0
            d_length = 0
            protocol = "icmp"
        elif isinstance(transporthdr, ImpactPacket.IGMP):
            s_port = 0
            d_port = 0
            seq_num = 0
            d_length = 0
            protocol = "igmp"
        else:
            s_port = 0
            d_port = 0
            seq_num = 0
            d_length = 0
            protocol = transporthdr.__class__

        if d_length == 0:
            return

        ports = port_to_vector(d_port)
        if ports is None:
            return

        grams = get_byte_freq(transporthdr.get_data_as_string(), d_length)

        id = "{}-{}-{}-{}-{}".format(s_addr, s_port, d_addr, d_port, protocol)

        if len(labels) == 0:
            line = "{},{},{},{}".format("0", v_protocol, port_to_vector(d_port), d_length)
        elif labels.has_key(id):
            line = "{},{},{},{}".format(labels[id], v_protocol, port_to_vector(d_port), d_length)
        else:
            line = "{},{},{},{}".format("0", v_protocol, port_to_vector(d_port), d_length)
            #print "{} not found\n".format(id)
            #raise Exception("id not found")

        for value in grams.itervalues():
            line += ",{}".format(round(value, 3))

        flabels.write(line + "\n")


def port_to_vector(port):
    ports = {20: '0', 21: '0', 22: '0', 23: '0', 25: '0', 53: '0', 80: '0', 110: '0', 139: '0', 143: '0', 443: '0', 445: '0'}

    if port in ports:
        ports[port] = '1'
        return ",".join(ports[key] for key in sorted(ports))
    else:
        return None


def read_pcap(data_date, flabels, labels):
    dataset_dir = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"
    if data_date != "11jun":
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

        cap = pcapy.open_offline(dataset_dir + "testbed-" + date_to_filename[filename] + ".pcap")
    else:
        cap = pcapy.open_offline(dataset_dir + "testbed-11jun.pcap")

    while(1):
        (header, packet) = cap.next()
        if not header:
            break
        parse_packet(flabels, labels, header, packet)


def get_byte_freq(payload, length):
    c = Counter()
    arr_payload = []
    grams = dict.fromkeys(range(0, 256), 0)

    for ch in list(payload):
        arr_payload.append(ord(ch))

    c.update(arr_payload)
    for gram, value in c.items():
        #print str(gram) + "(" + str(value) + ")"
        value = value/float(length)
        grams[gram] = value

    return grams


if __name__ == '__main__':
	main(sys.argv)