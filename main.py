import scapy.all as scapy
from binascii import hexlify
import pyshark
import sys
file = sys.argv[1]
cap = scapy.rdpcap(file)
pcap = pyshark.FileCapture(file)
output_file_name = '.'.join(file.split('/')[-1].split('.')[0:-1])
output_path = '/'.join(file.split('/')[0:-1]) + '/' + output_file_name + '.edited'
show = []
counter = 0
counter1 = 0
pcap.load_packets()

for p in cap:
    if 'gsm_map' in pcap[counter] and 'forwardSM (46)' in str(pcap[counter].gsm_map):
        length = pcap[counter].gsm_sms.tp_user_data_length
        pkt = p.__bytes__()
        pkthex = str(hexlify(pkt))
        sms_length = int(length)
        sms_string = "a" * sms_length * 3
        edited_sms = ((str.encode(sms_string[0:(sms_length * 2)]).hex()))
        edited_bytes = pkthex[:-7+12-(sms_length * 2)] + edited_sms + pkthex[-5:]
        finalstr = (bytes.fromhex(edited_bytes[2:-1]))
        show.append(finalstr)
    else:
        show.append(p)
    counter += 1

for line in show:
    counter1 += 1
    scapy.wrpcap('%s.pcap' % output_path, line, append=True, sync=True)
