import os
import sys
from scapy.utils import RawPcapReader
from scapy.all import *
from scapy.layers.tls.record import TLS
import socket


def process_pcap(file_name):
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
    print ("Cantidad de paquetes analizados: {}".format(count))

def count_access(file_name,ip_dest):
    count = 0
    ip_victim = ""
    data = ""

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        ethernet_data = Ether(pkt_data)
        if 'type' not in ethernet_data.fields:
            continue

        if ethernet_data.type != 0x0800:
            continue

        ip_data = ethernet_data[IP]

        if ip_data.dst == ip_dest:
            tcp_data = ip_data[TCP]
            if tcp_data.haslayer(TLS):
                count += 1


    print ("Existe al menos {} paquetes de posible envio de credenciales".format(count) )
    



def validate_path(file_name):
    if not os.path.isfile(file_name):
        return False
    else:
        return True

if __name__ == '__main__':

    #file_name = input("Ingrese ruta y nombre del archivo en formato pcap: ")
    file_name = "./test.pcap"

    if not validate_path(file_name):
        print('"{}" No existe el archivo .pcap'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    else:
        #domain = input("Ingrese dominio a anlizar: ")
        domain = "github.com"
        #ip_dest = socket.gethostbyname(domain)
        ip_dest = "140.82.113.3"  # quitar

    process_pcap(file_name)
    count_access(file_name,ip_dest)

    sys.exit(0)
