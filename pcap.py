import os
import sys
from scapy.utils import RawPcapReader
from scapy.all import *
from scapy.layers.tls.record import TLS
import socket

class bcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE  = '\033[97m'

class banner:
    def __init__(self):
        flag = """
          =======================================================================================================
          *       ********     ******     **       **   **         **     ******    **           '``'           *
          *          **       **    **     **     **    ** **      **   **     **   **          '- framet'?''   *
          *          **       **    **      **   **     **  **     **   **     **   **            ''    ''      *
          *          **       **    **       ** **      **    **   **   *********   **                          *
          *          **       **    **        ***       **     **  **   **     **   **                          *
          *     **   **       **    **         **       **      *****   **     **   **       **                 *
          *      *****         ******          **       **        ***   **     **   ***********                 *
          =======================================================================================================
            """
        print(bcolor.GREEN + flag)

def process_pcap(file_name):
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
    print ("Cantidad de paquetes analizados: {}".format(count))

def count_access(file_name,ip_dest):
    count = 0
    ip_victim = []

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
                if not ip_data.src in ip_victim:
                    ip_victim.append (ip_data.src)
    if len(ip_victim) > 0:
        print (bcolor.WHITE +  "----------- Informe de Resultados ---------")
        print (bcolor.WHITE + "Existe al menos {} paquetes analizados que contienen "\
                " posible envio de datos".format(count) )
        print (bcolor.WHITE + "Listados de Ips: " + "\n" + "----------------")
        for data in ip_victim:
            print (bcolor.GREEN + data)
        return True
    return False

def validate_path(file_name):
    if not os.path.isfile(file_name):
        return False
    else:
        return True

if __name__ == '__main__':
    banner = banner()
    print(bcolor.RED + "Mode" + "\n" +"[1] Auto Testing" + "\n" + "[2] Manual Testing")
    if input("Select: " + bcolor.GREEN) == "1":
        file_name = "./test.pcap"
        domain = "studio.code.org"
        ip_dest = "13.33.57.181"
    else:
        file_name = input("Ingrese ruta y nombre del archivo en formato pcap: ")
        if not validate_path(file_name):
            print(bcolor.RED +'"{}" No existe el archivo .pcap'.format(file_name), file=sys.stderr)
            sys.exit(-1)
        else:
            domain = input(bcolor.GREEN + "Ingrese dominio a analizar: ")
            ip_dest = socket.gethostbyname(domain)

process_pcap(file_name)
print (bcolor.RED + "Dominio: " + bcolor.GREEN + format(domain) + " -- " + bcolor.RED + "IP domain: " \
       + bcolor.GREEN + ip_dest)
if count_access(file_name,ip_dest) == False:
    print ("No existe paquetes sospechosos enviados al dominio: {}".format(domain))
sys.exit(0)
