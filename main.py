import re

import scapy.all as scapy
from binascii import hexlify
import pyshark
import sys
import os
from pathlib import Path

latin_sms_factor = 7 / 8

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

def substring_finder(start_index, time):
    start_object = start_index
    start_index = start_object + 16 + pkthex[start_object + 16:].find(time)
    return start_index

def lengthgen(layer):
    length = int(layer.tp_user_data_length)
    if layer.tp_dcs == '8':
        sms_length = length
    else:
        sms_length = int(length * latin_sms_factor) if ((length * latin_sms_factor) * 2) % 2 == 0 else (int((length * latin_sms_factor))) + 1
    return sms_length

def string_editor(layer, sms_length, start_index, pkthex):
    sms_string = "a" * sms_length * 3 #generate a long sms string
    if "User Data Header Length" in str(layer):
        edited_sms = ((str.encode(sms_string[0:(sms_length - 7)]).hex()))
        edited_bytes = pkthex[:(start_index + 16 + 14)] + edited_sms + pkthex[
                                                                       start_index + 16 + (sms_length * 2):]
    else:
        edited_sms = ((str.encode(sms_string[0:(sms_length)]).hex()))
        edited_bytes = pkthex[:(start_index + 16)] + edited_sms + pkthex[start_index + 16 + (sms_length * 2):]
    return bytes.fromhex(edited_bytes[2:-1])
def pcap_writer(output_path):
    counter1 = 0
    for line in show:
        counter1 += 1
        scapy.wrpcap('%s.pcap' % output_path, line, append=True, sync=True)

def path_gen(dirname, full_path):
    Path('/'.join(dirname.split('/')[0:-2]) + "/edited_files").mkdir(parents=True, exist_ok=True)
    output_file_name = '.'.join(full_path.split('/')[-1].split('.')[0:-1])
    output_path = '/'.join(full_path.split('/')[0:-2]) + '/edited_files/' + output_file_name + '.edited'
    return output_path

dirname = sys.argv[1]

for filename in os.listdir(dirname):
    print("editing %s please wait ..." % filename)
    full_path = dirname + '/' + filename
    output_path = path_gen(dirname, full_path)
    cap = scapy.rdpcap(full_path)
    pcap = pyshark.FileCapture(full_path)
    show = []
    counter = 0
#    pcap.load_packets()
    for packet in pcap:
        finalstr = cap[counter]
        pkthex = str(hexlify(finalstr.__bytes__()))
        start_index = 0
        start_object = 0
        for layer in packet:
            if "SMS text" in str(layer):
                time = timegen(layer)
                start_index = substring_finder(start_index, time)
                sms_length = lengthgen(layer)
                finalstr = string_editor(layer, sms_length, start_index, pkthex)
                pkthex = str(hexlify(finalstr))
        show.append(finalstr)
        counter += 1
        print(counter)

    pcap_writer(output_path)
