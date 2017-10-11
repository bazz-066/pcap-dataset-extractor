#!/usr/bin/python

import hashlib
import os
import pcapy
import sys
import time

from impacket import ImpactDecoder, ImpactPacket
from lxml import etree

def main(argv):
    try:
        os.environ['TZ'] = 'Europe/London'
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
            parsed["start_time"] = record.find("startDateTime").text.replace("T", " ")
            parsed["stop_time"] = record.find("stopDateTime").text.replace("T", " ")

            save_label(labels, parsed)
            #bpf_src = "src host " + parsed["src_address"]
            #bpf_dst = "dst host " + parsed["dst_address"]
            #bpf_src_port = "src port " + parsed["src_port"]
            #bpf_dst_port = "dst port " + parsed["dst_port"]

        print("Labels are stored, reading pcap files...\n")
        try:
            read_pcap(argv[1], labels)
        except pcapy.PcapError as e:
            print e

        print("Done\n")
    except IndexError as e:
        print e.message
        print "Usage : python iscx_dataset_splitter.py <labelled filename>"


def save_label(labels, parsed):
    id = "{}-{}-{}-{}-{}".format(parsed["src_address"], parsed["src_port"], parsed["dst_address"], parsed["dst_port"], parsed["protocol"])
    id_rev = "{}-{}-{}-{}-{}".format(parsed["dst_address"], parsed["dst_port"], parsed["src_address"], parsed["src_port"], parsed["protocol"])

    # minus 4 hours spare 10 minutes before and after the written time
    start_time = convert_epochfromstring(parsed['start_time']) + 13800
    stop_time = convert_epochfromstring(parsed['stop_time']) + 15000

    for i in range(0, 1000):
        if labels.has_key(id + "-{}".format(i)):
            continue
        else:
            id += "-{}".format(i)
            id_rev += "-{}".format(i)
            break

    labels[id] = {'label': parsed["label"], 'start_time': start_time, 'stop_time': stop_time}
    labels[id_rev] = {'label': parsed["label"], 'start_time': start_time, 'stop_time': stop_time}


def convert_timefromepoch(epochTimestamp):
    return time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(epochTimestamp))


def convert_epochfromstring(timeString):
    pattern = '%Y-%m-%d %H:%M:%S'
    epoch = int(time.mktime(time.strptime(timeString, pattern)))
    return epoch


def parse_packet(labels, dumper, header, packet):
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(packet)

    ts = int(header.getts()[0])
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
            d_length = -1
            protocol = transporthdr.__class__

        #if d_length == 0 and (protocol == "tcp_ip" or protocol == "udp_ip"):
        #    return

        id = "{}-{}-{}-{}-{}".format(s_addr, s_port, d_addr, d_port, protocol)
        is_label_found = False

        for i in range(0, 1000):
            tmp_id = id + "-{}".format(i)
            if labels.has_key(tmp_id):
                if ts > labels[tmp_id]["start_time"] and ts < labels[tmp_id]["stop_time"]:
                    # print convert_timefromepoch(ts), convert_timefromepoch(labels[tmp_id]["start_time"]), convert_timefromepoch(labels[tmp_id]["stop_time"])
                    if labels[tmp_id]["label"] == "Normal":
                        dumper[0].dump(header, packet)
                    else:
                        dumper[1].dump(header, packet)

                    is_label_found = True
                    break
                else:
                    continue
            else:
                continue

        if not is_label_found:
            dumper[2].dump(header, packet)


def read_pcap(data_date, labels):
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
    dataset_dir = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"

    cap = pcapy.open_offline(dataset_dir + "testbed-" + date_to_filename[filename] + ".pcap")
    dumper = []
    dumper.append(cap.dump_open(dataset_dir + "testbed-" + date_to_filename[filename] + "-normal.pcap"))
    dumper.append(cap.dump_open(dataset_dir + "testbed-" + date_to_filename[filename] + "-attack.pcap"))
    dumper.append(cap.dump_open(dataset_dir + "testbed-" + date_to_filename[filename] + "-unknown.pcap"))
    counter = 0

    # for i in range(0,1000):
    while(1):
        (header, packet) = cap.next()

        if not header:
            break
        parse_packet(labels, dumper, header, packet)
        counter += 1
        sys.stdout.write("\rProcessed {} packets.".format(counter))
        sys.stdout.flush()


if __name__ == '__main__':
	main(sys.argv)