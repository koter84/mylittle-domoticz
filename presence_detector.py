#!/usr/bin/python
#   File : check_beacon_presence.py
#   Author: jmleglise
#   Date: 10-Nov-2016
#   Description : Check the presence of a list of beacon (BlueTooth Low Energy V4.0) and update a url using a HTTP-GET
#   URL : https://github.com/koter84/presence_detector/
#   Forked-From : https://github.com/jmleglise/mylittle-domoticz/
#   Version : 1.0
#   Version : 1.1   Log + Mac Adress case insensitive
#   Version : 1.2   Fix initial AWAY state
#   Version : 1.3   Log + script takes care of hciconfig + Return the RSSI when detected and "AWAY" otherwise
#   Version : 1.4   Fix initial HOME state
#   Version : 1.5   Split loglevel warning / debug
#   Version : 1.6   Add le_handle_connection_complete +  Manage Domoticz login
#   Version : 2.0   Koter84 : Cleanup and leave only SWITCH_MODE, Remove DOMOTICZ linking
#
# Feature :
# Script takes care of Bluetooth Adapter. Switch it UP RUNNING.
# When the MACADRESS of a list of beacons are detected, do a HTTP-GET
# For beacon in range, update only 1 time the uservariable with "HOME". And "AWAY" otherwise.
# Send "AWAY" when the beacons are not in range.
# The detection is very fast : around 4 seconds. And the absence is verified every 5 seconds by comparing the time of the last presence with a time out for each beacon.
#
# References :
# https://www.domoticz.com/wiki/Presence_detection_%28Bluetooth_4.0_Low_energy_Beacon%29
# http://https://www.domoticz.com/forum/viewtopic.php?f=28&t=10640
# https://wiki.tizen.org/wiki/Bluetooth
# https://storage.googleapis.com/google-code-archive-source/v2/code.google.com/pybluez/source-archive.zip  => pybluez\examples\advanced\inquiry-with-rssi.py
#
# Usefull command
# sudo /etc/init.d/check_beacon_presence [stop|start|restart|status]
#
# Configuration :
# Change your IP and Port here :
POST_URL = 'http://192.168.32.91/OpenDOM/tracker.php?type=BLE&hostname=PARAM_HOSTNAME&name=PARAM_NAME&status=PARAM_STATUS'
POST_USER=''
POST_PASS=''

#
# Configure your Beacons in the TAG_DATA table with : [Name,MacAddress,Timeout,0,mode]
# Name : the name of the beacon
# macAddress : case insensitive
# Timeout is in secondes the elapsed time  without a detetion for switching the beacon AWAY. Ie :if your beacon emits every 3 to 8 seondes, a timeout of 15 secondes seems good.
# 0 : used by the script (will keep the time of the last broadcast)

TAG_DATA = [
    ["Pinkie","ce:02:47:09:2f:f9",120,0],
    ["Greenie","c4:83:87:6d:90:8d",120,0]
]


import logging

# choose between DEBUG (log every information) or WARNING (change of state) or CRITICAL (only error)
logLevel=logging.DEBUG
#logLevel=logging.WARNING
#logLevel=logging.CRITICAL

#logOutFilename='/var/log/check_beacon_presence.log'       # output LOG : File or console (comment this line to console output)
ABSENCE_FREQUENCY=5  # frequency of the test of absence. in seconde. (without detection, switch "AWAY".

################ Nothing to edit under this line #####################################################################################

import os
import subprocess
import sys
import struct
import time
import signal
import threading

if os.path.isdir("/storage/.kodi/") :
    sys.path.insert(0, '/storage/.kodi/addons/service.presence.detector/lib')

import bluetooth._bluetooth as bluez
import requests

if os.path.isdir("/storage/.kodi/") :
    import xbmc
    import xbmcgui
    import xbmcaddon
    __addon__   = xbmcaddon.Addon()

    class Settings(object):
        def __init__(self):
#            xbmc.log('PD> Settings.__init__()', xbmc.LOGNOTICE)
            self.enabled         = True
            self.notifications   = True
            self.load()

        def getSetting(self, name, dataType = str):
#            xbmc.log('PD> Settings.getSetting()', xbmc.LOGNOTICE)
            value = __addon__.getSetting(name)
            if dataType == bool:
                if value.lower() == 'true':
                    value = True
                else:
                    value = False
            elif dataType == int:
                value = int(value)
            else:
                value = str(value)
#            xbmc.log('PD> getSetting:' + str(name) + '=' + str(value), xbmc.LOGNOTICE)
            return value

        def setSetting(self, name, value):
#            xbmc.log('PD> Settings.setSetting()', xbmc.LOGNOTICE)
            if type(value) == bool:
                if value:
                    value = 'true'
                else:
                    value = 'false'
            else:
                value = str(value)
#            xbmc.log('PD> setSetting:' + str(name) + '=' + str(value), xbmc.LOGNOTICE)
            __addon__.setSetting(name, value)

        def getLocalizedString(self, stringid):
#            xbmc.log('PD> Settings.getLocalizedString()', xbmc.LOGNOTICE)
            return __addon__.getLocalizedString(stringid)

        def load(self):
#            xbmc.log('PD> Settings.load()', xbmc.LOGNOTICE)
            self.enabled            = self.getSetting('enabled', bool)
            self.notifications      = self.getSetting('notifications', bool)


LE_META_EVENT = 0x3e
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_ENABLE=0x000C
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02

def print_packet(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)

def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

if not os.path.isdir("/storage/.kodi/") :
    def handler(signum = None, frame = None):
        time.sleep(1)  #here check if process is done
        sys.exit(0)

    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, handler)

def le_handle_connection_complete(pkt):
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    device_address = packed_bdaddr_to_string(pkt[5:11])
    interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])
    #print "le_handle_connection output"
    #print "status: 0x%02x\nhandle: 0x%04x" % (status, handle)
    #print "role: 0x%02x" % role
    #print "device address: ", device_address

def request_thread(name, status):
    try:
        url = POST_URL
        hostname = os.uname()[1]
        url=url.replace('PARAM_HOSTNAME',str(hostname))
        url=url.replace('PARAM_NAME',str(name))
        url=url.replace('PARAM_STATUS',str(status))
        logging.warning(url)
        result = requests.get(url,auth=(POST_USER, POST_PASS))
        logging.debug(" %s -> %s" % (threading.current_thread(), result))
    except requests.ConnectionError, e:
        logging.critical(' %s Request Failed %s - %s' % (threading.current_thread(), e, url) )

class CheckAbsenceThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):

        time.sleep(ABSENCE_FREQUENCY)
        for tag in TAG_DATA:
            elapsed_time_absence=time.time()-tag[3]
            if elapsed_time_absence>=tag[2] : # sleep execute after the first Home check.
                logging.warning('Tag %s not seen since %i sec => update absence',tag[0],elapsed_time_absence)
                threadReqAway = threading.Thread(target=request_thread,args=(tag[0],"AWAY"))
                threadReqAway.start()

        while True:
            time.sleep(ABSENCE_FREQUENCY)
            for tag in TAG_DATA:
                elapsed_time_absence=time.time()-tag[3]
                if elapsed_time_absence>=tag[2] and elapsed_time_absence<(tag[2]+ABSENCE_FREQUENCY) :  # update when > timeout ant only 1 time , before the next absence check [>15sec <30sec]
                    logging.warning('Tag %s not seen since %i sec => update absence',tag[0],elapsed_time_absence)
                    threadReqAway = threading.Thread(target=request_thread,args=(tag[0],"AWAY"))
                    threadReqAway.start()

def main():
    if os.path.isdir("/storage/.kodi/") :
        global dialog, dialogprogress, responseMap, settings, monitor
        dialog = xbmcgui.Dialog()
        dialogprogress = xbmcgui.DialogProgress()
        settings = Settings()
        xbmc.log('PD> Settings.__init__()', xbmc.LOGNOTICE)

    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if globals().has_key('logOutFilename') :
        logging.basicConfig(format=FORMAT,filename=logOutFilename,level=logLevel)
    else:
        logging.basicConfig(format=FORMAT,level=logLevel)

    #Reset Bluetooth interface, hci0
    if os.path.isdir("/storage/.kodi/") :
        os.system("hciconfig hci0 down")
        os.system("hciconfig hci0 up")
    else:
        os.system("sudo hciconfig hci0 down")
        os.system("sudo hciconfig hci0 up")

    #Make sure device is up
    if os.path.isdir("/storage/.kodi/") :
        interface = subprocess.Popen(["hciconfig"], stdout=subprocess.PIPE, shell=True)
    else:
        interface = subprocess.Popen(["sudo hciconfig"], stdout=subprocess.PIPE, shell=True)
    (output, err) = interface.communicate()

    if "RUNNING" in output: #Check return of hciconfig to make sure it's up
        logging.debug('Ok hci0 interface Up n running !')
    else:
        logging.critical('Error : hci0 interface not Running. Do you have a BLE device connected to hci0 ? Check with hciconfig !')
        sys.exit(1)

    devId = 0
    try:
        sock = bluez.hci_open_dev(devId)
        logging.debug('Connect to bluetooth device %i',devId)
    except:
        logging.critical('Unable to connect to bluetooth device...')
        sys.exit(1)

    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    hci_toggle_le_scan(sock, 0x01)

    for tag in TAG_DATA:
        tag[3]=time.time()-tag[2]  # initiate lastseen of every beacon "timeout" sec ago. = Every beacon will be AWAY. And so, beacons here will update

    th=CheckAbsenceThread()
    th.daemon=True
    th.start()

    while True:
        old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
        sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])

        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            i = 0
        elif event == bluez.EVT_NUM_COMP_PKTS:
            i = 0
        elif event == bluez.EVT_DISCONN_COMPLETE:
            i = 0
        elif event == LE_META_EVENT:
            subevent, = struct.unpack("B", pkt[3])
            pkt = pkt[4:]
            if subevent == EVT_LE_CONN_COMPLETE:
                le_handle_connection_complete(pkt)
            elif subevent == EVT_LE_ADVERTISING_REPORT:
                num_reports = struct.unpack("B", pkt[0])[0]
                report_pkt_offset = 0
                for i in range(0, num_reports):
                    #logging.debug('UDID: ', print_packet(pkt[report_pkt_offset -22: report_pkt_offset - 6]))
                    #logging.debug('MAJOR: ', print_packet(pkt[report_pkt_offset -6: report_pkt_offset - 4]))
                    #logging.debug('MINOR: ', print_packet(pkt[report_pkt_offset -4: report_pkt_offset - 2]))
                    #logging.debug('MAC address: ', packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]))
                    #logging.debug('Unknown:', struct.unpack("b", pkt[report_pkt_offset -2])) # don't know what this byte is.  It's NOT TXPower ?
                    #logging.debug('RSSI: %s', struct.unpack("b", pkt[report_pkt_offset -1])) #  Signal strenght !
                    macAdressSeen=packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                    for tag in TAG_DATA:
                        if macAdressSeen.lower() == tag[1].lower():  # MAC ADDRESS
                            logging.debug('Tag %s Detected %s - RSSI %s - DATA unknown %s', tag[0], macAdressSeen, struct.unpack("b", pkt[report_pkt_offset -1]),struct.unpack("b", pkt[report_pkt_offset -2])) #  Signal strenght + unknown (hope it's battery life).
                            elapsed_time=time.time()-tag[3]  # lastseen
                            if elapsed_time>=tag[2] : # Upadate only once : after an absence (>timeout). It's back again
                                logging.warning('Tag %s seen after an absence of %i sec : update presence',tag[0],elapsed_time)
                                threadReqHome = threading.Thread(target=request_thread,args=(tag[0],"HOME")) # name, HOME
                                threadReqHome.start()
                            tag[3]=time.time()   # update lastseen

        sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

if __name__ == '__main__':
    main()
