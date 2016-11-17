#!/usr/bin/python

import pcapy
import sys

from impacket import ImpactDecoder, ImpactPacket

def main(argv):
    try:
        fdataset = open(argv[1], "r")
        labels = {}
        attackers = []
        victims = []
        bpf_attackers = ""
        bpf_victims = ""
        ports_attack = []
        bpf_ports_attack = ""
        ports_victim = []
        bpf_ports_victim = ""

        for line in fdataset.readlines():
            line = line.strip()

            if line == "":
                #print labels, ports_attack, ports_victim, bpf_attackers, bpf_victims, bpf_ports_attack, bpf_ports_victim
                try:
                    read_pcap(labels, bpf_attackers, bpf_victims, bpf_ports_attack, bpf_ports_victim)
                    if len(labels) > 0:
                        print labels["ID"] + " " + labels["Date"]
                except pcapy.PcapError as e:
                    print labels["ID"] + " " + labels["Date"] + ":" + str(e)
                    continue
                    #else:
                    #    print str(e)
                    #    break
                labels = {}
                attackers = []
                victims = []
                bpf_attackers = ""
                bpf_victims = ""
                ports_attack = []
                ports_victim = []
                bpf_ports_attack = ""
                bpf_ports_victim = ""
            elif line.find("Attacker") == 0:
                key, value = parse(line.strip())
                if value is not None:
                    bpf_attackers, attackers = parse_address("src", value)
            elif line.find("Victim") == 0:
                key, value = parse(line.strip())
                if value is not None:
                    bpf_victims, victims = parse_address("dst", value)
            elif line.find("At_Attacker") == 0:
                key, value = parse(line.strip())
                if value is not None:
                    bpf_ports_attack, ports_attack = parse_port("src", value)
            elif line.find("At_Victim") == 0:
                key, value = parse(line.strip())
                if value is not None:
                    bpf_ports_victim, ports_victim = parse_port("dst", value)
            else:
                key, value = parse(line.strip())
                labels[key] = value

    except IndexError as e:
        print "Usage : python darpa_dataset_extractor.py <labelled filename>"
    except KeyboardInterrupt:
        print "bye bye"


def parse(line):
    options = line.split(": ", 2)

    if len(options) == 2:
        return options[0], options[1]
    else:
        return options[0], None

def parse_address(direction, line):
    options = line.split(", ")
    addresses = []
    bpf_address = "("
    counter = 0
    num_address = len(options)

    if line.find(".") < 0:
        addresses.append(line)
        return "", addresses

    for address in options:
        try:
            octets = address.split(".")
            if address.find("-") < 0 and octets[3] != '*':
                tmp_address = str(int(octets[0])) + "." + str(int(octets[1])) + "." + str(int(octets[2])) + "." + str(int(octets[3]))
                addresses.append(tmp_address)
                bpf_address += direction + " host " + tmp_address
            elif octets[3] == '*':
                for last_octet in range(1, 255):
                    tmp_address = str(int(octets[0])) + "." + str(int(octets[1])) + "." + str(int(octets[2])) + "." + str(last_octet)
                    addresses.append(tmp_address)
                bpf_address += direction + " net " + str(int(octets[0])) + "." + str(int(octets[1])) + "." + str(int(octets[2]))
            else:
                tmp_octet = octets[3].split("-")

                for last_octet in range(int(tmp_octet[0]), int(tmp_octet[1]) + 1):
                    tmp_address = str(int(octets[0])) + "." + str(int(octets[1])) + "." + str(int(octets[2])) + "." + str(last_octet)
                    addresses.append(tmp_address)
                    bpf_address += direction + " host " + tmp_address
                    if last_octet != (int(tmp_octet[1])):
                        bpf_address += " or "

            counter += 1
            if counter < num_address:
                bpf_address += " or "
        except ValueError:
            addresses.append(address)
            num_address -= 1

    if counter == 0:
        bpf_address = ""
    else:
        bpf_address += ") "

    return bpf_address, addresses

def parse_port(direction, line):
    options = line.split(", ")
    ports = []
    bpf_port = " ("
    counter = 0
    num_ports = len(options)

    for port in options:
        tmp_port = port[:port.find("{")]
        ports.append(tmp_port)
        if tmp_port.isdigit():
            counter += 1
            bpf_port += direction + " port " + tmp_port
        elif tmp_port.find("-") > 0:
            counter += 1
            bpf_port += direction + " portrange " + tmp_port
        elif tmp_port == 'i':
            counter += 1
            bpf_port += "ip proto \\icmp"
        else:
            num_ports -= 1

        if counter < num_ports and len(bpf_port) > 2:
            bpf_port += " or "

    if counter == 0:
        bpf_port = ""
    else:
        bpf_port += ") "

    return bpf_port, ports


def parse_packet(flabels, att_id, header, packet):
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(packet)

    #print str(ether.get_ether_type()) + " " + str(ImpactPacket.IP.ethertype)

    if ether.get_ether_type() == ImpactPacket.IP.ethertype:
        iphdr = ether.child()
        transporthdr = iphdr.child()
        if transporthdr.get_data_as_string() != '' and isinstance(transporthdr, ImpactPacket.TCP):
            s_addr = iphdr.get_ip_src()
            d_addr = iphdr.get_ip_dst()
            s_port = transporthdr.get_th_sport()
            d_port = transporthdr.get_th_dport()
            d_length = transporthdr.get_size()
            seq_num = transporthdr.get_th_seq()

            flabels.write("{},{},{},{},{},{},{}\n".format(s_addr, s_port, d_addr, d_port, seq_num, d_length, att_id))


def read_pcap(label, bpf_attackers, bpf_victims, bpf_port_attacks, bpf_port_victims):
    if len(label) == 0:
        return

    date_to_filename = {'03/29/1999' : '4/monday/inside',
                        '03/30/1999' : '4/tuesday/inside',
                        '03/31/1999' : '4/wednesday/inside',
                        '04/01/1999' : '4/thursday/inside',
                        '04/02/1999' : '4/friday/inside',
                        '04/05/1999' : '5/monday/inside',
                        '04/06/1999' : '5/tuesday/inside',
                        '04/07/1999' : '5/wednesday/inside',
                        '04/08/1999' : '5/thursday/inside',
                        '04/09/1999' : '5/friday/inside',
                        }
    dataset_dir = "/home/baskoro/Documents/Dataset/DARPA99/week"

    cap = pcapy.open_offline(dataset_dir + date_to_filename[label["Date"]] + ".tcpdump")
    dumper = cap.dump_open("att-vic-week" + date_to_filename[label["Date"]].replace("/", "-") + label["ID"] + ".pcap")
    filter = ""

    if len(bpf_attackers) > 0:
        filter += bpf_attackers

    if len(bpf_victims) > 0:
        if len(bpf_attackers) == 0:
            filter += bpf_victims
        elif len(bpf_attackers) > 0:
            filter += " and " + bpf_victims

    if len(bpf_port_victims) > 0:
        if len(bpf_attackers) > 0 or len(bpf_victims) > 0:
            filter += " and " + bpf_port_victims
        else:
            filter += bpf_port_victims

    #print filter
    cap.setfilter(filter)
    flabels = open("att-vic-week" + date_to_filename[label["Date"]].replace("/", "-") + ".csv", "a")

    while(1):
        (header, packet) = cap.next()
        if not header:
            break
        dumper.dump(header, packet)
        parse_packet(flabels, label["ID"], header, packet)

    flabels.close()
    if len(bpf_port_attacks) <= 0:
        return

    cap = pcapy.open_offline(dataset_dir + date_to_filename[label["Date"]].replace("inside", "outside") + ".tcpdump")
    dumper = cap.dump_open("vic-att-week" + date_to_filename[label["Date"]].replace("/", "-").replace("inside", "outside") + label["ID"] + ".pcap")
    filter = ""

    if len(bpf_attackers) > 0:
        filter += bpf_attackers.replace("src", "dst")
    if len(bpf_victims) > 0:
        if len(bpf_attackers) == 0:
            filter += bpf_victims.replace("dst", "src")
        elif len(bpf_attackers) > 0:
            filter += " and " + bpf_victims.replace("dst", "src")
    if len(bpf_port_attacks) > 0:
        if len(bpf_attackers) > 0 or len(bpf_victims) > 0:
            filter += " and " + bpf_port_attacks.replace("src", "dst")
        else:
            filter += bpf_port_attacks.replace("src", "dst")

    #print filter
    cap.setfilter(filter)
    flabels = open("vic-att-week" + date_to_filename[label["Date"]].replace("/", "-").replace("inside", "outside") + ".csv", "a")

    while (1):
        (header, packet) = cap.next()
        if not header:
            break
        dumper.dump(header, packet)
        parse_packet(flabels, label["ID"],  header, packet)

    flabels.close()


if __name__ == '__main__':
	main(sys.argv)