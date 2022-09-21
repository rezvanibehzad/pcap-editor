import re

import scapy.all as scapy
from binascii import hexlify
import pyshark
import sys
import os
from pathlib import Path
def timegen(lyr):
    stryear = str(layer.scts_year)
    year = stryear[1] + stryear[0] if len(stryear) == 2 else stryear + '0'
    strmonth = str(layer.scts_month)
    month = strmonth[1] + strmonth[0] if len(strmonth) == 2 else strmonth + '0'
    strday = str(layer.scts_day)
    day = strday[1] + strday[0] if len(strday) == 2 else strday + '0'
    strhour = str(layer.scts_hour)
    hour = strhour[1] + strhour[0] if len(strhour) == 2 else strhour + '0'
    strminutes = str(layer.scts_minutes)
    minutes = strminutes[1] + strminutes[0] if len(strminutes) == 2 else strminutes + '0'
    strseconds = str(layer.scts_seconds)
    seconds = strseconds[1] + strseconds[0] if len(strseconds) == 2 else strseconds + '0'
    time = year + month + day + hour + minutes + seconds
    return time

def lengthgen(lyr):
    length = int(layer.tp_user_data_length)
    if layer.tp_dcs == '8':
        sms_length = length
    else:
        sms_length = int((length * 7) / 8) if (((length * 7) / 8) * 2) % 2 == 0 else (int(((length * 7) / 8))) + 1
    return sms_length

dirname = sys.argv[1]
Path('/'.join(dirname.split('/')[0:-2]) + "/edited_files").mkdir(parents=True, exist_ok=True)

for filename in os.listdir(dirname) :
    print("editing %s please wait ..." % filename)
    full_path = dirname + '/' + filename
    cap = scapy.rdpcap(full_path)
    pcap = pyshark.FileCapture(full_path)
    output_file_name = '.'.join(full_path.split('/')[-1].split('.')[0:-1])
    output_path = '/'.join(full_path.split('/')[0:-2]) + '/edited_files/' + output_file_name + '.edited'
    print(output_path)
    show = []
    counter = 0
    counter1 = 0
    pcap.load_packets()
    for packet in pcap:
        p = cap[counter]
        finalstr = ''
        if 'gsm_map' in packet and 'forwardSM (46)' in str(packet.gsm_map):
            pkt = p.__bytes__()
            pkthex = str(hexlify(pkt))
            start_index = 0
            start_object = 0
            for layer in packet:
                if "SMS text" in str(layer):
                    time = timegen(layer)
                    start_object = start_index
                    start_index = start_object + 16 + pkthex[start_object + 16:].find(time)
                    sms_length = lengthgen(layer)
                    sms_string = "a" * sms_length * 3
                    if "User Data Header Length" in str(layer):
                        edited_sms = ((str.encode(sms_string[0:(sms_length-6)]).hex()))
                        edited_bytes = pkthex[:(start_index + 16+12)] + edited_sms + pkthex[
                                                                                  start_index + 16 + (sms_length * 2):]
                    else:
                        edited_sms = ((str.encode(sms_string[0:(sms_length)]).hex()))
                        edited_bytes = pkthex[:(start_index+16)] + edited_sms + pkthex[start_index+16+(sms_length*2):]
                    finalstr = (bytes.fromhex(edited_bytes[2:-1]))
                    pkthex = str(hexlify(finalstr))
            show.append(finalstr)
        else:
            show.append(p)
        counter += 1
        print(counter)

for line in show:
    counter1 += 1
    scapy.wrpcap('%s.pcap' % output_path, line, append=True, sync=True)
