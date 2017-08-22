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
        dataset_dir = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"

        flabels = open(dataset_dir + "csv/short-csv-" + date_to_filename[filename] + ".csv", "a")
        fdataset = etree.parse(argv[1], etree.XMLParser(ns_clean=True, recover=True))
        root = fdataset.getroot()

        print("Num of traffic : " + str(len(root.getchildren())))

        for record in root.getchildren():
            parsed = {}
            try:
                parsed["src_address"] = record.find("source").text
                parsed["dst_address"] = record.find("destination").text
                parsed["src_port"] = record.find("sourcePort").text
                parsed["dst_port"] = record.find("destinationPort").text
                parsed["protocol"] = record.find("protocolName").text
                parsed["app_name"] = record.find("appName").text
                parsed["direction"] = record.find("direction").text
                parsed["start"] = record.find("startDateTime").text
                parsed["stop"] = record.find("stopDateTime").text
                parsed["label"] = record.find("Tag").text
                save_label(flabels, parsed)
            except AttributeError:
                print(etree.tostring(record))


            #bpf_src = "src host " + parsed["src_address"]
            #bpf_dst = "dst host " + parsed["dst_address"]
            #bpf_src_port = "src port " + parsed["src_port"]
            #bpf_dst_port = "dst port " + parsed["dst_port"]

        print("Labels have been stored\n")

        flabels.close()
        print("Done\n")
    except IndexError as e:
        print "Usage : python icsx_dataset_xml_to_csv.py <labelled filename>"


def save_label(flabels, parsed):
    flabels.write("{},{},{},{},{},{},{},{},{},{}\n".format(parsed["src_address"], parsed["src_port"], parsed["dst_address"], parsed["dst_port"], parsed["protocol"], parsed["app_name"], parsed["direction"], parsed["start"], parsed["stop"], parsed["label"]))


if __name__ == '__main__':
	main(sys.argv)