import time
import scapy.all as scapy
from binascii import hexlify
import pyshark
import sys
import os
from pathlib import Path

latin_sms_factor = 7 / 8
jump = 16  # place between time and sms string
data_header = 14


def timegen(lyr):
    stryear = str(lyr.scts_year)
    year = stryear[1] + stryear[0] if len(stryear) == 2 else stryear + '0'
    strmonth = str(lyr.scts_month)
    month = strmonth[1] + strmonth[0] if len(strmonth) == 2 else strmonth + '0'
    strday = str(lyr.scts_day)
    day = strday[1] + strday[0] if len(strday) == 2 else strday + '0'
    strhour = str(lyr.scts_hour)
    hour = strhour[1] + strhour[0] if len(strhour) == 2 else strhour + '0'
    strminutes = str(lyr.scts_minutes)
    minutes = strminutes[1] + strminutes[0] if len(strminutes) == 2 else strminutes + '0'
    strseconds = str(lyr.scts_seconds)
    seconds = strseconds[1] + strseconds[0] if len(strseconds) == 2 else strseconds + '0'
    timestr = year + month + day + hour + minutes + seconds
    return timestr


def substring_finder(number, substr):
    strt_object = number
    number = strt_object + jump + pkthex[strt_object + 16:].find(substr)
    return number


def lengthgen(lyr):
    length = int(lyr.tp_user_data_length)
    if lyr.tp_dcs == '8':
        s_length = length
    else:
        s_length = int(length * latin_sms_factor) if ((length * latin_sms_factor) * 2) % 2 == 0 else (int((
                                                                                                                      length * latin_sms_factor))) + 1
    return s_length


def string_editor(lyr, length, number, pkt):
    sms_string = "a" * length * 3  # generate a long sms string
    if "User Data Header Length" in str(lyr):
        edited_sms = (str.encode(sms_string[0:(length - 7)]).hex())
        edited_bytes = pkt[:(number + jump + data_header)] + edited_sms + pkt[
                                                               number + jump + (length * 2):]
    else:
        edited_sms = (str.encode(sms_string[0:length]).hex())
        edited_bytes = pkt[:(number + jump)] + edited_sms + pkt[number + jump + (length * 2):]
    return bytes.fromhex(edited_bytes[2:-1])


def pcap_writer(path):
    counter1 = 0
    for line in show:
        counter1 += 1
        scapy.wrpcap('%s.pcap' % path, line, append=True, sync=True)


def path_gen(name):
    pth = dirname + '/' + filename
    Path('/'.join(name.split('/')[0:-1]) + "/edited_files").mkdir(parents=True, exist_ok=True)
    output_file_name = '.'.join(pth.split('/')[-1].split('.')[0:-1])
    out_path = '/'.join(pth.split('/')[0:-2]) + '/edited_files/' + output_file_name + '.edited'
    return out_path


def new_path(name):
    pth = dirname + '/' + filename
    Path('/'.join(name.split('/')[0:-1]) + "/origin_files").mkdir(parents=True, exist_ok=True)
    output_file_name = '.'.join(pth.split('/')[-1].split('.')[0:-1])
    os.replace(pth, '/'.join(pth.split('/')[0:-2]) + '/origin_files/' + output_file_name + ".pcap")


dirname = sys.argv[1]
for filename in os.listdir(dirname):
    full_path = dirname + '/' + filename
    age = time.time() - os.stat(full_path).st_mtime
    if age > 360:
        print("editing %s please wait ..." % filename)
        output_path = path_gen(dirname)
        cap = scapy.rdpcap(full_path)
        pcap = pyshark.FileCapture(full_path)
        show = []
        counter = 0
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
        new_path(dirname)
        pcap_writer(output_path)
