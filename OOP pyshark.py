import pyshark
import asyncio
import csv

class pcapReader(object):
    def __init__(self, usr_agnt, host, method, counter, src_port, dst_port, src_ip, dst_ip, protocol_to_show):
        self.usr_agnt = usr_agnt
        self.host = host
        self.method = method
        self.counter = counter
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol_to_show = protocol_to_show



    def print_packet_info():
        pkts = pyshark.FileCapture('pcapFile.pcap')
        # Create CSV file
        with open('outputFile.csv', 'w', newline='') as f:
            fieldnames = ['Protocol', 'Src Port', 'Dst Port', 'Src IP', 'Dst IP', 'User-Agent', 'HTTP Host', 'HTTP Method']
            thewriter = csv.DictWriter(f, fieldnames=fieldnames)
            thewriter.writeheader()

            # Getting data from packets
            try:
                usr_agnt = None
                host = None
                method = None
                counter = 0
                for p in pkts:
                    counter += 1
                    print(f"\nPacket Number: {counter}")

                    # Protocol
                    protocol = p.ip.proto

                    # Ports
                    src_port = p.tcp.srcport
                    dst_port = p.tcp.dstport

                    # IPs
                    src_ip = p.ip.src
                    dst_ip = p.ip.dst


                    if hasattr(p, 'tcp'):
                        print(f"Src IP: {src_ip}")
                        print(f"Dst IP: {dst_ip}")
                        print(f"Src Port: {src_port}")
                        print(f"Dst Port: {dst_port}")
                        if protocol == 6:
                            protocol_to_show = "HTTP"
                        else:
                            protocol_to_show = "TCP"
                            print(f"Protocol: {protocol_to_show}\n")

                    if hasattr(p, 'http'):
                        if p.ip.src == "10.0.0.2":
                            # User Agent
                            usr_agnt = p.http.user_agent
                            # Host
                            host = p.http.host
                            # HTTP Method
                            method = p.http.request_method
                            print(f"Method: {method}")
                            print(f"Host: {host}")
                            print(f"User-Agent: {usr_agnt}")
                        else:
                            pass
                    # Write fields on the csv file
                    thewriter.writerow(
                        {'Protocol': protocol_to_show, 'Src Port': src_port, 'Dst Port': dst_port, 'Src IP': src_ip,
                         'Dst IP': dst_ip, 'User-Agent': usr_agnt, 'HTTP Host': host, 'HTTP Method': method})
            except OSError:
                pass
            except asyncio.TimeoutError:
                pass
            finally:
                pkts.close()

pcapReader.print_packet_info()
