#!/usr/bin/python

import os
import pandas as pd
import pcapy
import sys
import traceback

from impacket import ImpactDecoder, ImpactPacket

# mode options: step or batch
mode = "batch"


def main(argv):
    try:
        pcap_directory = argv[1]
        unsw_csv = load_csv_dataset(pcap_directory)

        read_pcaps(unsw_csv, pcap_directory)
    except IndexError as e:
        print traceback.print_exc()
        print("Usage: python unsw_nb15_dataset_splitter.py <pcap_directory>")


def load_csv_dataset(pcap_directory):
    pcap_date = pcap_directory.split("/")[-1]
    unsw_csv = pd.read_csv("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15 Source-Files/UNSW-NB15 - CSV Files/UNSW-NB15_1.csv", header=None, dtype={1: object, 3: object, 47: object})

    for i in range(2,5):
        tmp = pd.read_csv("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15 Source-Files/UNSW-NB15 - CSV Files/UNSW-NB15_{}.csv".format(str(i)), header=None, dtype={1: object, 3: object, 47: object})
        unsw_csv = unsw_csv.append(tmp)
        print("loaded ", i)

    unsw_csv = unsw_csv.drop_duplicates()
    if pcap_date == "pcaps 22-1-2015":
        unsw_csv = unsw_csv[unsw_csv[28].values < 1424131200]
    elif pcap_date == "pcaps 17-2-2015":
        unsw_csv = unsw_csv[unsw_csv[28].values >= 1424131200]
    else:
        raise Exception("Directory doesn't exist")

    print("CSV Length: ", len(unsw_csv))
    return unsw_csv


def read_pcaps(unsw_csv, pcap_directory):
    pcap_date = pcap_directory.split("/")[-1]
    print(pcap_directory)
    print(pcap_date)
    if pcap_date == "pcaps 22-1-2015":
        stop = 3
        # stop = 54
    elif pcap_date == "pcaps 17-2-2015":
        stop = 28
    else:
        raise Exception("Directory doesn't exist")

    attack_types = ["Generic", "Exploits", "Fuzzers", "Reconnaissance", "DoS", "Backdoors", "Analysis", "Shellcode", "Worms"]

    for i in range(2, stop):
        cap = pcapy.open_offline("{}/{}.pcap".format(pcap_directory, str(i)))
        dumper = {}
        dumper["normal"] = cap.dump_open("{}/normal/{}.pcap".format(pcap_directory, str(i)))
        for type in attack_types:
            dumper[type] = cap.dump_open("{}/attack/{}-{}.pcap".format(pcap_directory, str(i), type))
        dumper["unknown"] = cap.dump_open("{}/unknown/{}.pcap".format(pcap_directory, str(i)))

        counter = 0

        while(True):
        # for j in range(0, 1000):
            (header, packet) = cap.next()

            if not header:
                break

            parse_packet(unsw_csv, dumper, header, packet)
            counter += 1
            sys.stdout.write("\rCalculated {} packets from {}.pcap.".format(counter, i))
            sys.stdout.flush()


def parse_packet(unsw_csv, dumper, header, packet):
    decoder = ImpactDecoder.LinuxSLLDecoder()
    ether = decoder.decode(packet)

    ts = int(round(float(str(header.getts()[0]) + "." + str(header.getts()[1]))))
    # print str(ether.get_ether_type()) + " " + str(ImpactPacket.IP.ethertype)

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
            protocol = "tcp"
        elif isinstance(transporthdr, ImpactPacket.UDP):
            s_port = transporthdr.get_uh_sport()
            d_port = transporthdr.get_uh_dport()
            seq_num = 0
            d_length = transporthdr.get_uh_ulen()
            protocol = "udp"
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

        if mode == "batch":
            rows = filter_row(s_addr, s_port, d_addr, d_port, ts, unsw_csv)
            # print(s_addr, s_port, d_addr, d_port, ts)

            # packet lies in between start and stop time
            if len(rows) >= 1:
                row = rows.iloc[[0]]
                if row[48].values == 0:
                    dumper["normal"].dump(header, packet)
                    return
                else:
                    type = row[47].values[0].strip()
                    dumper[type].dump(header, packet)
                    return
            else:
                rows = filter_row(d_addr, d_port, s_addr, s_port, ts, unsw_csv)

                if len(rows) >= 1:
                    row = rows.iloc[[0]]
                    if row[48].values == 0:
                        dumper["normal"].dump(header, packet)
                        return
                    else:
                        type = row[47].values[0].strip()
                        dumper[type].dump(header, packet)
                        return
                else:
                    dumper["unknown"].dump(header, packet)
        elif mode == "step":
            rows = unsw_csv[((unsw_csv[0].values == s_addr) & (unsw_csv[1].values == str(s_port)) & (unsw_csv[2].values == d_addr) & (unsw_csv[3].values == str(d_port))) |
            ((unsw_csv[0].values == d_addr) & (unsw_csv[1].values == str(d_port)) & (unsw_csv[2].values == s_addr) & (unsw_csv[3].values == str(s_port)))
            ]

            if len(rows) >= 0:
                row = show_option(s_addr, s_port, d_addr, d_port, ts, rows)

                if row is None:
                    dumper["unknown"].dump(header, packet)
                elif row[48].values == 0:
                    dumper["normal"].dump(header, packet)
                    return
                else:
                    type = row[47].values[0].strip()
                    dumper[type].dump(header, packet)
                    return
            else:
                dumper["unknown"].dump(header, packet)


def filter_row(s_addr, s_port, d_addr, d_port, ts, unsw_csv):
    a = unsw_csv[unsw_csv[0].values == s_addr]
    b = a[a[1].values == str(s_port)]
    c = b[b[2].values == d_addr]
    d = c[c[3].values == str(d_port)]
    e = d[(d[28].values - 1 <= ts) & (d[29].values + 1 >= ts)]

    return e


def show_option(s_addr, s_port, d_addr, d_port, ts, rows):
    os.system("clear")
    print("Packet Information:")
    print("Source Address\tSource Port\tDestination Address\tDest Port\tArrival Time")
    print("{}\t{}\t{}\t{}\t{}\n\n".format(s_addr, s_port, d_addr, d_port, ts))

    rows = rows.assign(time_diff=(rows[28] - ts))
    rows = rows.sort_values(by=['time_diff'])

    print("Matching Rows:")
    print("Source Address\tSource Port\tDestination Address\tDest Port\tStart Time\tEnd Time")

    for index, row in rows.iterrows():
        print("{}\t{}\t{}\t{}\t{}\t{}".format(row[0], str(row[1]), row[2], str(row[3]), row[28], row[29]))

    user_input = raw_input("Which is the matched row? [(F)irst/(Row Number)/(A)uto first/(N)o match]")

    if user_input.upper() == "F":
        return rows.iloc[[0]]
    elif user_input.upper() == "N":
        return None
    elif user_input.upper() == "A":
        mode = "batch"
        return rows.iloc[[0]]
    else:
        try:
            row_index = int(user_input)
            return rows.iloc[[row_index]]
        except ValueError:
            return rows.iloc[[0]]


if __name__ == '__main__':
	main(sys.argv)