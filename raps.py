#!/usr/bin/python

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
    x = 0

    parser = argparse.ArgumentParser(usage='Find Rogue Access Points within scanning range')
    parser.add_argument('-s', '--show', action='store_true', help='Shows the current databases')
    parser.add_argument('-a', '--auto', action='store_true', help='Run in Auto Mode',) #maybe make this the default without flags?
    parser.add_argument('-c', '--clean', dest='cleandb', help='Clean Databases, Accepts k/r/u')
    parser.add_argument('-u', '--unknown', action='store_true', help='View the Unknown database',)
    parser.add_argument('-i', '--interface', help='Interface to Scan on')

    args = parser.parse_args()

    try:
        conn=pymongo.MongoClient()
    except pymongo.errors.ConnectionFailure, e:
        print "Could not connect to MongoDB: %s" % e
        sys.exit()

    #define mongo DBs
    db = conn.aps
    collk = db.known_aps
    collu = db.unknown_aps
    collr = db.rogue_aps

    if args.unknown:
        if collu.count({}) > 0: #check if there's actually any APs in the db
            print "The Unknown Database has %s Records" % collu.count()
            if raw_input("Do you want to organise the Unkown DB into Known and Rogue? [y/N]").find("y") != -1:
                for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
                    print u
                    ap = {"SSID":str(u[u'SSID']), "BSSID":str(u[u'BSSID']), "LANMAC":str(u[u'LANMAC'])}
                    print ap
                    if raw_input("Which Database Would You Like to Add This to? [k/R]") == "k":
                        collk.insert(ap)
                    else:
                        collr.insert(ap)
                    collu.remove({"SSID":str(u[u'SSID']), "BSSID":str(u[u'BSSID']), "LANMAC":str(u[u'LANMAC'])})
            else:
                for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
                    print u
        else:
            print "The Unknown Database is Empty."

    if args.cleandb:
        if args.cleandb.find('k') != -1:
            print "Cleaning Known DB"
            collk.remove({})
        if args.cleandb.find('r') != -1:
            print "Cleaning Rogue DB"
            collr.remove({})
        if args.cleandb.find('u') != -1:
            print "Cleaning Unknown DB"
            collu.remove({})

    if args.show:
        print "Known DB:"
        for k in collk.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
            print k
        print "Unknown DB:"
        for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
            print u
        print "Rogue DB:"
        for r in collr.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
            print r

    if args.auto:
        print 'Running RAPS in auto mode'

        scanWifi(args.interface)
        macs, ssids = readDump()

        for m in macs:
            doTheMongo(db, collk, collu, collr, ssids[x], macs[x])
            x = x + 1

def mongoInit(db, collk, collu, collr, ssid, bssid, lanmac):
    ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
    collk.insert(ap)
    collu.insert(ap)
    collr.insert(ap)

def scanWifi(scanint):
    global ipath

    #call(['airmon-ng', 'start', scanint])
    Popen("airmon-ng start %s" % scanint, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(5)
    monint = 'mon0'
    aircom = "airodump-ng --output-format csv --write %s/rapsdump %s" % (ipath, monint)
    p = Popen([aircom], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(20)
    os.kill(p.pid, SIGTERM)
    call(['airmon-ng', 'stop', monint])

def readDump(): #parse the wifi dump .csv for MACs and SSIDs
    global ipath
    f = []
    macs = []
    ssids = []
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
    os.remove("%s/rapsdump-01.csv" % ipath)
    #return the 2 lists
    return macs, ssids

def doTheMongo(db, collk, collu, collr, ssid, bssid):
    """
    Return codes:
        -1 - Not on LAN
        -2 - Multiple matching MACs on LAN
         1 - Matched Known AP
         2 - Matched Rogue AP
         3 - Added AP to Unkown DB
    """
    #if lanman doesn't find anything, automatically add the AP to collu as it's not on the LAN
    lanmac = findLanMac(bssid)
    if lanmac == 0:
        print "AP with SSID %s, BSSID %s is not on the LAN." % (ssid, bssid)
        ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
        collu.insert(ap)
        return -1
    elif lanmac == 1:
        print "Multiple MACs found, please search for the device manually!"
        return -2
    else:
        print "Lanmac Found for SSID: %s & BSSID: %s is %s" % (ssid, bssid, lanmac)

    if collk.count({}) > 0: #check if there's actually any APs in the db
        for k in collk.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
            if str(k[u'SSID']) == ssid: #check ssid match
                if str(k[u'BSSID']) == bssid:
                    if str(k[u'LANMAC']) == lanmac:
                        #if a RAP has all these, there would be switching errors
                        #which will be more obvious to network managers
                        print "Expected SSID %s, all elements match." % ssid
                        return 1
                    else:
                        print "Did you forget to add an AP to the known database?:\n%s, %s, %s\nChecking Rogue for Safety." % (ssid, bssid, lanmac)
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            #launch unknown func here
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
                else:
                    if str(k[u'LANMAC']) == lanmac:
                        print "Did you forget to add an AP to the known database?:\n%s, %s, %s\nChecking Rogue for Safety." % (ssid, bssid, lanmac)
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                                print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                                ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                                collu.insert(ap)
                            else:
                                print "Already in Unknown DB, please launch with -u flag to review."
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
                    else:
                        print "Only matched on SSID %s, checking against the Rogue DB." % ssid
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                                print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                                ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                                collu.insert(ap)
                            else:
                                print "Already in Unknown DB, please launch with -u flag to review."
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
            else:
                print "No SSID match on %s, checking Rogue DB." % ssid
                if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                    print "Not in Rogue DB, checking Unknown DB."
                    if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                        print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                        ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                        collu.insert(ap)
                    else:
                        print "Already in Unknown DB, please launch with -u flag to review."
                    return 3
                else:
                    print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 2

    else: #in case there's nothing in the db
        print "There is nothing in the known database, running init function."
        mongoInit(db, collk, collu, collr, "Init", "DE:AD:BE:EF:CO:FE", "DE:AD:BE:EF:CO:FE")
        print "Being recursive with SSID: %s & BSSID: %s & LANMAC: %s" % (ssid, bssid, lanmac)
        doTheMongo(db, collk, collu, collr, ssid, bssid)

def checkRogue(db, collk, collu, collr, ssid, bssid, lanmac):
    for r in collr.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
        if str(r[u'SSID']) == ssid: #check ssid match
            if str(r[u'BSSID']) == bssid:
                if str(r[u'LANMAC']) == lanmac:
                    print "Full RAP Match:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID and BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(r[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID." % (ssid, bssid, lanmac)
                    return 1
        else:
            if str(r[u'BSSID']) == bssid:
                if str(r[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on BSSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(a[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on LANMAC." % (ssid, bssid, lanmac)
                    return 1

def checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac):
    for u in collu.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
        if str(u[u'SSID']) == ssid: #check ssid match
            if str(u[u'BSSID']) == bssid:
                if str(u[u'LANMAC']) == lanmac:
                    print "Full Unknown Match:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID and BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID." % (ssid, bssid, lanmac)
                    return 1
        else:
            if str(u[u'BSSID']) == bssid:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on BSSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on LANMAC." % (ssid, bssid, lanmac)
                    return 1

def findLanMac(bssid): #takes the bssid and finds the lan mac of the AP
#Returns:
#XX:XX:XX:XX:XX:XX - Found MAC
#0                 - Not Found
#1                 - Found Multiple MACs that match
    found = 0
    vendor = bssid[:8]
    matchMe = bssid[:-1]
    foundMAC = ""

    while len(matchMe) > 8:
        if matchMe[len(matchMe) - 1] == ":":
            matchMe = matchMe[:-1]

        snmp = snmpRead()
        for s in snmp:
            s = s.replace(" ", ":")
            if s.find(matchMe) != -1:
                foundMAC = s
                found = found + 1
        if found == 1:
            return foundMAC
        elif found > 1:
            print "Multiple matching MACs found, do something else with this later!"
            return 1
        matchMe = matchMe[:-1]
        return 0

def snmpAsk():
    Popen('snmpwalk -v 2c -c fyp 192.168.1.4 1.3.6.1.2.1.17.4.3.1.1 > /opt/raps/mib.txt', stdin=PIPE, stdout=PIPE, shell=True)
    time.sleep(5)

def snmpRead():
    mArr = []
    f2 = open("/opt/raps/mib.txt", 'r')
    for line in f2:
        line = line.split(': ')
        line = line[1]
        mArr.append(line[0:17])
    f2.close()
    return mArr

if __name__ == "__main__":
    main(sys.argv)
