import struct
import io
import re
import sys
import socket
import ssl
from struct import Struct
import packet_struct
'''
https://realpython.com/python-data-structures/#structstruct-serialized-c-structs
'''

ETHERNET_H_SZ=14
PACKET_H_SZ=16
GLOBAL_H_SZ=24

GLOBAL_P=[]


def main():
    
    try:
        fn=readAndCheck()
        openAndProcess(fn)
    except:
        print("error opening cap file")
        sys.exit()
    

def readAndCheck():
    '''
    performs error checking on user input
    '''
    fileName=""
    try:
        fileName=sys.argv[1]
    except:
        sys.exit()
    if len(sys.argv) < 2:
        print("Error: invalid length")
        sys.exit()
    return fileName


def openAndProcess(fileName):
    '''
    open the provided file, read data, call helper functions


    param fileName:    name of the capfile     
    returns:           nothing
    '''
    #f=open("sample-capture-file.cap","rb")
    #f=open("s1.cap","rb")
    #f=open("s2.cap","rb")
    #f=open("s3.cap","rb")
    f=open(fileName,"rb")
    pcapFile=f.read()
    var1=True
    globalHeaderBinary, restOfFile=readFile(pcapFile,GLOBAL_H_SZ)
    globalHeader=getGlobalHeader(globalHeaderBinary)
    endianess=globalHeader.endian
    newArr=[]
    count=0
    while restOfFile>bytes(0):
        restOfFile,addToArray=getNextPacket(restOfFile,endianess,count)
        newArr.append(addToArray)
        count+=1
    arr2=GLOBAL_P
    numConnections=[]
    count=0
    while len(arr2)>0:
        #print(arr2[count])
        arr2, con=sort(arr2,numConnections, var1)
        count+=1
    print("A) Total connections: "+str(numPackets(numConnections)))
    print("----------------------------------")
    print("")
    print("B) Connections Details ")
    x=formatResults(con, numConnections)
    print("----------------------------------")
    print("")
    print("C) General ")
    print("Total number of complete TCP connections: "+str(numPackets(numConnections)))
    rstConn=getNumResetsHelper1(GLOBAL_P)
    print("Number of reset TCP connections: "+str(rstConn))
    print("Number of TCP connections that were still open when the trace capture ended: "+str(numPackets(numConnections)))
    print("----------------------------------")
    print("D) Complete TCP connections")
    

def formatResults(packet, inputConnectionsArray):
    '''
    print information about each TCP connection

    param packet:                   the TCP connections (small)
    param inputConnectionsArray:    all packets in the file (large)
    returns:                        <list> 
    '''
    result=[]
    count=0
    for packet in inputConnectionsArray:
        el1=packet_struct.summaryInfo()
        el1.populateFields(packet)
        el1.formatResultsHelp()
        result.append(el1)
        count+=1
    return result


def numPackets(inArray):
    """
    total connections counter, init development
    """
    count=0
    for x in inArray:
        count+=1
    return count    


def getGlobalHeader(inHeader):
    '''
    create a global header object and populate with data

    param inHeader:     first 24 bytes of the cap file
    returns:            <packet_struct.globalHeader> 
                        the global header object
    ''' 
    globH_obj1=packet_struct.globalHeader()
    globH_obj1.get_Global_H(inHeader)
    return globH_obj1


def sort(a,b,var):
    '''
    build list to determine connection info
             
    '''
    top=a[0]
    result=a,b
    try:
        l1=top.getIPandTCPheader()
    except:
        print("error get TCP")
    inList = False
    for i,pack in enumerate(b):
        t1 = pack[0].getIPandTCPheader()
        if l1[0] in t1 and var==True:
            if l1[1] in t1 and var==True:
                inList=True
                pack.append(top)
                b[i]=pack
                #print(b[i])
                #print("=============")
                result=a[1:], b
                return result
    if not inList:
        #print("here")
        pack=[top]
        b.append(pack)
        return a[1:], b


def getNextPacket(inPacketHeader,endianess,numPackets):
    '''
    read packets and update the remaining binary file

    param inPacketHeader:   the cap file
    param endianess:        little or big
    param numPackets:       a count of each packet
    returns:                <bytes> inPacketHeader: the remaining cap file
                            <packet_struct.packet> packetObj1: the processed packet extracted from cap file 
    '''
    pHeader,inPacketHeader=readFile(inPacketHeader,PACKET_H_SZ)
    obj1=packet_struct.packet()
    dataSize=obj1.getInclLen(pHeader,endianess,numPackets)
    nextData,inPacketHeader=readFile(inPacketHeader,dataSize)
    obj1.packetData(nextData)
    GLOBAL_P.append(obj1)
    return inPacketHeader, obj1


def readFile(inFile, lengthToRead):
    '''
    read part of the input file

    param inFile:       the binary data
    param lengthToRead: length to stop the first packet at
    returns:            <bytes> startPacket: the first packet in a series of possibly many
                        <bytes> remainingPackets: all the rest of the packets               
    '''
    startPacket=inFile[0:lengthToRead]
    remainingPackets=inFile[lengthToRead:]
    return startPacket,remainingPackets


def getNumResetsHelper1(inPacketsArr):
    for px in inPacketsArr:
        t1=px.getflags()
        count=0
        if (t1['RST']==1):
            count+=1
    return count


def getNumConnectionsHelper1(inPackets,next,outputArr):
    p1=inPackets[next]
    t1=p1.getflags()
    if (t1['ACK']==1) and (t1['SYN']==1):
        outputArr.append(p1) 
    return outputArr


if __name__=='__main__':
    main()