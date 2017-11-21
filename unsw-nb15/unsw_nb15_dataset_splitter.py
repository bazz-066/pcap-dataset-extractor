#!/usr/bin/python

import os
import pandas as pd
import pcapy
import psycopg2
import sys
import thread
import threading
import time
import traceback

from impacket import ImpactDecoder, ImpactPacket

# mode options: step or batch
mode = "batch"
MAX_THREAD = 4
num_thread = 0
counters = {}
list_thread = []


def main(argv):
    try:
        pcap_directory = argv[1]
        # unsw_csv = load_csv_dataset(pcap_directory)

        read_pcaps(pcap_directory)
        # read_pcaps(unsw_csv, pcap_directory)
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


# def read_pcaps(unsw_csv, pcap_directory):
def read_pcaps(pcap_directory):
    pcap_date = pcap_directory.split("/")[-1]
    print(pcap_directory)
    print(pcap_date)
    if pcap_date == "pcaps 22-1-2015":
        # stop = 13
        stop = 54
    elif pcap_date == "pcaps 17-2-2015":
        stop = 28
    else:
        raise Exception("Directory doesn't exist")

    index = 1
    print index, stop
    while index < stop:
        if num_thread < MAX_THREAD:
            t = PcapReader(pcap_directory, index)
            t.start()
            list_thread.append(t)
            index += 1
            time.sleep(1)
        else:
            time.sleep(1)

        sys.stdout.write("\r")

        for i, counter in counters.iteritems():
            sys.stdout.write("{} packets from {}.pcap, ".format(counter, i))

        sys.stdout.flush()

    while not are_all_thread_finished():
        sys.stdout.write("\r")

        for i, counter in counters.iteritems():
            sys.stdout.write("{} packets from {}.pcap, ".format(counter, i))

        sys.stdout.flush()
        time.sleep(1)


def are_all_thread_finished():
    if len(list_thread) == 0:
        return False

    for t in list_thread:
        if t.done == False:
            return False

    return True


class PcapReader(threading.Thread):
    def __init__(self, pcap_directory, index):
        threading.Thread.__init__(self)
        self.pcap_directory = pcap_directory
        self.index = index
        self.done = False

    def run(self):
        global num_thread
        global MAX_THREAD
        global counters

        num_thread += 1
        attack_types = ["Generic", "Exploits", "Fuzzers", "Reconnaissance", "DoS", "Backdoors", "Analysis", "Shellcode", "Worms"]

        conn = psycopg2.connect(host="localhost", database="unsw_nb15", user="postgres", password="postgres")
        cur = conn.cursor()
        cap = pcapy.open_offline("{}/{}.pcap".format(self.pcap_directory, str(self.index)))
        dumper = {}
        dumper["normal"] = cap.dump_open("{}/normal/{}.pcap".format(self.pcap_directory, str(self.index)))
        for attack_type in attack_types:
            dumper[attack_type] = cap.dump_open("{}/attack/{}-{}.pcap".format(self.pcap_directory, str(self.index), attack_type))
        dumper["unknown"] = cap.dump_open("{}/unknown/{}.pcap".format(self.pcap_directory, str(self.index)))

        counters[str(self.index)] = 0

        while (True):
            # for j in range(0, 1000):
            (header, packet) = cap.next()

            if not header:
                break

            # parse_packet(unsw_csv, dumper, header, packet)
            self.parse_packet(cur, dumper, header, packet)
            counters[str(self.index)] += 1

        cur.close()
        conn.close()

        num_thread -= 1
        del counters[str(self.index)]
        self.done = True

    def parse_packet(self, cur, dumper, header, packet):
        try:
            decoder = ImpactDecoder.LinuxSLLDecoder()
            ether = decoder.decode(packet)
        except IndexError:
            dumper["unknown"].dump(header, packet)
            return
        except ImpactPacket.ImpactPacketException:
            dumper["unknown"].dump(header, packet)
            return

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
                rows = self.filter_row(s_addr, s_port, d_addr, d_port, ts, cur)
                # print(s_addr, s_port, d_addr, d_port, ts)

                # packet lies in between start and stop time
                if rows is not None:
                    #row = rows[0]

                    if rows[5] == 0:
                        dumper["normal"].dump(header, packet)
                        return
                    else:
                        attack_type = rows[4].strip()
                        if attack_type == "Backdoor":
                            attack_type = "Backdoors"
                        dumper[attack_type].dump(header, packet)
                        return
                else:
                    rows = self.filter_row(d_addr, d_port, s_addr, s_port, ts, cur)

                    if rows is not None:
                        #row = rows[0]
                        #print(row)
                        if rows[5] == 0:
                            dumper["normal"].dump(header, packet)
                            return
                        else:
                            attack_type = rows[4].strip()
                            if attack_type == "Backdoor":
                                attack_type = "Backdoors"
                            dumper[attack_type].dump(header, packet)
                            return
                    else:
                        dumper["unknown"].dump(header, packet)
            elif mode == "step":
                # This part hasn't been tested YET
                cur.execute("select * from records where srcip=%s and sport=%s and dstip=%s and dsport=%s and start_time-1<=%s and end_time+1>=%s", (s_addr, s_port, d_addr, d_port, ts, ts))
                rows = cur.fetchmany()

                if len(rows) >= 0:
                    row = self.show_option(s_addr, s_port, d_addr, d_port, ts, rows)

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

    def filter_row(self, s_addr, s_port, d_addr, d_port, ts, cur):
        # a = unsw_csv[unsw_csv[0].values == s_addr]
        # b = a[a[1].values == str(s_port)]
        # c = b[b[2].values == d_addr]
        # d = c[c[3].values == str(d_port)]
        # e = d[(d[28].values - 1 <= ts) & (d[29].values + 1 >= ts)]
        cur.execute("select * from records where srcip=%s and sport=%s and dstip=%s and dsport=%s and start_time-1<=%s and end_time+1>=%s", (s_addr, s_port, d_addr, d_port, ts, ts))
        row = cur.fetchone()

        return row

    def show_option(self, s_addr, s_port, d_addr, d_port, ts, rows):
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