#!/usr/bin/python

"""
RAPS - Rogue AP Scanner(Suite)

author: bi0dr0ned at gmail

General TODO:

- Use threading for things because parallelisation
- Implement attack methods once an AP is found
    - Reaver
    - Honeypot
- Use curses or some form of GUI to display log file to terminal
- Add an install option
- Have a DB of known default SSIDs for quick detection
- Fix mongo DBs because currently everything is going towards the known APs DB,
    need to go to unknown if not in known as known will be preconfigured (or possibly set up on first run?)
- Have a point that the user can see the contents of the unknown DB and pick whether to add to known or rogue

"""

import os
from os import walk
import subprocess
import threading
import sys
import time
import argparse
import socket
from subprocess import Popen, PIPE, call
from signal import SIGINT, SIGTERM
import pymongo
import datetime
import csv

ipath = "/opt/raps"

def main(argv):
    global ipath

    parser = argparse.ArgumentParser(usage='Find rogue Access Points within scanning range')
    parser.add_argument('-t', '--temp', action='store_true', help='Real basic temp stuffs')
    parser.add_argument('-a', '--auto', action='store_true', help='Run in auto mode (assumes --fightback)',)
    parser.add_argument('-f', '--fightback', action='store_true', help='Fights back against Rogue AP with Reaver and Honey Pot')
    parser.add_argument('-i', '--interface', help='Interface to scan on')
    # parser.add_argument('-si', '--switchIP', help='IP Address of core switch(es) or file containing IP addresses')
    # parser.add_argument('-sc', '--snmpCommunity', help='SNMP Community of switches to be polled')
    # parser.add_argument('-sp', '--snmpPort', help='Port that SNMP operates on')

    #TODO: add arg for db location (or have a default location of /opt/raps)
    #TODO: have a flag to init the mongodb with a file or a list of MACs
    args = parser.parse_args()

    if args.auto: #TODO: Spawn a thread based on this
        print 'Running RAPS in auto mode'
        try:
            conn=pymongo.MongoClient()
            print "Connected successfully!!!"
        except pymongo.errors.ConnectionFailure, e:
            print "Could not connect to MongoDB: %s" % e
            sys.exit()

        #TODO: do some logic here to determine if a db exists already
        #define mongo DBs
        db = conn.aps
        collk = db.known_aps
        collu = db.unknown_aps
        collr = db.rogue_aps

        macs, ssids = readDump()
        mongoTests(db, collk, collu, collr)

        utc = datetime.datetime.utcnow()
        ssid = "kawaii-fi"
        bssid = "DE:AD:BE:EF:CO:FF"
        channel = "1"

    if args.temp:
        readDump()

def scanWifi(scanint):
    global ipath

    #put ifconfig stats into a temp file to find monitor interfaces
    tmp0 = open("/opt/raps/tmp.txt", 'w')
    Popen('ifconfig', stdin=PIPE, stdout=tmp0, stderr=PIPE, shell=True)
    tmp0.close() #maybe try doing this in the same file...?
    #read the temp file to see if monitor mode int exists
    tmp1 = open("/opt/raps/tmp.txt", 'r')
    if tmp1.read().find("mon") == -1:
        call(['airmon-ng', 'start', scanint])
        time.sleep(10)
    tmp1.close()
    monint = 'mon0' #TODO: Grab this from ifconfig file
    aircom = "airodump-ng --output-format csv --write %s/rapsdump %s" % (ipath, monint)
    p = Popen([aircom], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(10)
    os.kill(p.pid, SIGTERM)
    call(['airmon-ng', 'stop', monint]) #TODO: make more intelligent for different OSes?

def readDump(): #parse the wifi dump .csv for MACs and SSIDs
    global ipath
    f = []
    macs = []
    ssids = []

    #TODO: use this to get the latest file
    #get files in dir (for when there's multiple files)
    for (dirpath, dirnames, filenames) in walk(ipath):
        f.extend(filenames)
        break
    #print f
    fpath = "%s/rapsdump-01.csv" % ipath

    #parse .csv into a list for detail grabbing
    with open(fpath, 'rb') as f1:
        r = csv.reader(f1, delimiter='\n')
        l1 = list(r)

    for x in l1:
        if str(x).find("Station MAC") != -1: #filter out station macs
            break
        if str.find(str(x), ":") != -1: #only get macs in final list
            macs.append(str.strip(str.split(str(x), ',')[0], "[ '")) #split to only get MAC and then remove first 2 chars ([')
            ssids.append(str.strip(str.split(str(x), ',')[13])) #split to only get SSID and then remove whitespace
    #return the 2 lists
    return macs, ssids

def doTheMongo(db, collk, collu, collr):
    """
    Return codes:
        0 - No match
            Check SNMP match for Rogue AP
        1 - SSID match, BSSID match
            Check SNMP for Smart Evil Twin
        2 - SSID match, BSSID no match
            Check SNMP for Dumb Evil Twin or Smart Rogue AP
    """

    if collk.count({'SSID':ssid}) > 0: #check if there's actually any APs in the db
        for a in collk.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, '_id':0}): #check for matches with SSID
            if str(a[u'BSSID']) == bssid: #check for matches with BSSID
                print "Expected AP %s, all elements match." % str(a[u'SSID'])
                print "Check SNMP for Evil Twin Attack for safety."
                return 1
            else: #if BSSID doesn't match
                ap = {"BSSID":bssid, "SSID":ssid}
                collr.insert(ap)
                print "BSSID: " + bssid + " with SSID: " + ssid + " added to Rogue AP DB."
                return 2 #BSSID not found
        return 0
        # if apFound == 0:
        #     ap = {"BSSID":bssid, "SSID":ssid}
        #     collu.insert(ap)
        #     print "BSSID: " + bssid + " with SSID: " + ssid + " added to Unkown AP DB."
    else: #in case there's nothing in the db
        print "There is nothing in the known database, please run RAPS with the install flag set."
        sys.exit()

def snmpAsk():
    mArr = [] #array to hold MAC addresses from the MIB
    f1 = open("/opt/raps/mib.txt", 'w')
    Popen('snmpwalk -v 2c -c fyp 192.168.1.4 1.3.6.1.2.1.17.4.3.1.1', stdin=PIPE, stdout=f1, stderr=PIPE, shell=True)
    time.sleep(5)
    f1.close() #maybe try doing this in the same file...?

def snmpRead():
    f2 = open("/opt/raps/mib.txt", 'r')
    for line in f2:
        line = line.split(': ')
        line = line[1]
        mArr.append(line[0:17])
    f2.close()

def mongoTests(db, collk, collu, collr):
    print "collk has %s records." % collk.count()
    for a in collk.find(): #loops over the collection and prints each document
        print a
    print collk.find_one()
    print "collu has %s records." % collu.count()
    for a in collu.find(): #loops over the collection and prints each document
        print a
    print collu.find_one()
    print "collr has %s records." % collr.count()
    for a in collr.find(): #loops over the collection and prints each document
        print a
    print collr.find_one()
    #collk.remove({}) #remove all documents from collection
    #collu.remove({})
    #collr.remove({})

if __name__ == "__main__":
    main(sys.argv)
