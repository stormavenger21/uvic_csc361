import struct

#ip header
BIG_ENDIAN=0xD4C3B2A1
LITTLE_ENDIAN=0xA1B2C3D4

GLOBAL_H_SZ=24
PACKET_H_SZ=16
ETHERNET_H_SZ=14


class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def getIPinfo(self, binaryD):
        self.get_header_len(binaryD[0:1])
        ip4_header,binaryD=self.readbytes(binaryD,self.ip_header_len)
        self.get_total_len(ip4_header[2:4])
        self.get_IP(ip4_header[12:16],ip4_header[16:])
        return binaryD
 
    def readbytes(self,input,lengthToRead):
        startPacket=input[0:lengthToRead]
        remainingPackets=input[lengthToRead:]
        #print(input[0])
        return startPacket,remainingPackets
    

class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)

    def getTCPinfo(self, packetBinary):
        self.get_src_port(packetBinary[0:2])
        self.get_dst_port(packetBinary[2:4])
        self.get_seq_num(packetBinary[4:8])
        self.get_ack_num(packetBinary[8:12])
        self.get_data_offset(packetBinary[12:13])
        self.get_flags(packetBinary[13:14])
        self.get_window_size(packetBinary[14:15], packetBinary[15:16])
        return packetBinary
   
class packetHeader:
    tsSec=0.0
    tsUsec=0.0
    inclLen=0
    origLen=0

    
class packet():
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    orig_time=0
    incl_len=0
    endian=None
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.orig_time=0
        self.incl_len=0
        self.endian=None

    def getIPandTCPheader(self):
        return ([self.IP_header.src_ip, self.TCP_header.src_port],[self.IP_header.dst_ip, self.TCP_header.dst_port],)

    def __str__(self):
        return str(self.__class__)+": "+str(self.__dict__)
    
    def getInclLen(self,binData,endianess,numPackets):
        self.endian=endianess
        ts_sec=binData[0:4]
        ts_usec=binData[4:8]
        incl_len=struct.unpack(endianess+"I",binData[8:12])[0]
        self.timestamp_set(ts_sec,ts_usec,self.orig_time)
        self.packet_No_set(numPackets)
        self.incl_len=incl_len
        return incl_len
    
    def packetData(self, inputVal):
        inputVal=inputVal[ETHERNET_H_SZ:]
        inputVal=self.IP_header.getIPinfo(inputVal)
        inputVal=self.TCP_header.getTCPinfo(inputVal)

    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds=struct.unpack('I',buffer1)[0]
        microseconds=struct.unpack('<I',buffer2)[0]
        self.timestamp=round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

    def getflags(self):
        return self.TCP_header.flags

    
    def getLen(self):
        result=0
        hSize = self.IP_header.ip_header_len+self.TCP_header.data_offset
        len=self.IP_header.total_len
        result=len-hSize
        return result


class globalHeader:
    magicNumber=0 
    versionMajor=0 
    versionMinor=0 
    thisZone=0 
    sigFigs=0 
    snapLen=0 
    network=0 
    endian=None

    def __init__(self):
        self.magicNumber=0
        self.versionMajor=0
        self.versionMinor=0
        self.thisZone=0
        self.sigFigs=0
        self.snapLen-0
        self.network=0
        self.endian=None

    def get_Global_H(self, capFile):
        self.magic_number = struct.unpack("<I", capFile[0:4])[0]
        #print(self.magic_number)
        if self.magic_number == BIG_ENDIAN:
            self.endian=">"
        elif self.magic_number == LITTLE_ENDIAN:
            self.endian="<"
        else:
            self.endian="<"
        count2=0
        self.version_major=struct.unpack(self.endian+"H",capFile[4:6])[0]
        self.version_minor=struct.unpack(self.endian+"H",capFile[6:8])[0]
        self.thiszone=struct.unpack(self.endian+"i",capFile[8:12])[0]
        self.sigfigs=struct.unpack(self.endian+"I",capFile[12:16])[0]
        self.snaplen=struct.unpack(self.endian+"I",capFile[16:20])[0]
        self.network=struct.unpack(self.endian+"I",capFile[20:])[0]
        count2+=1
        #print(count2)

    def __str__(self):
        return str(self.__class__)+": "+str(self.__dict__)



class summaryInfo:
    count1=0
    numPacketsSRC=0
    numPacketsDEST=0
    totalPackets=0
    numBytesSRC=0
    numBytesDEST=0
    sourceAddress=None
    destinationAddress=None
    sourcePort=0
    destinationPort=0
    state=[]
    startTime=0
    endTime=0
    duration=0
    totalBytes=0
    window_list=None
    complete=None
    received=None
    sent=None 


    def __init__(self):
        summaryInfo.count1+=1
        self.count1=summaryInfo.count1
        self.numPacketsSRC=0
        self.numPacketsDEST=0
        self.totalPackets=0
        self.numBytesSRC=0
        self.numBytesDEST=0
        self.sourceAddress=None
        self.destinationAddress=None
        self.sourcePort=0
        self.destinationPort=0
        self.state=[0,0,0]
        self.startTime=0
        self.endTime=0
        self.duration=0
        self.window_list=[]
        self.totalBytes=0
        self.complete=False
        self.received=[]
        self.sent=[]

    
    def populateFields(self,inPacket):
        p0=inPacket[0]
        p1IP=p0.IP_header
        p1TCP=p0.TCP_header
        self.sourcePort=p1TCP.src_port
        self.destinationPort=p1TCP.dst_port
        self.sourceAddress=p1IP.src_ip
        self.destinationAddress=p1IP.dst_ip
        '''
        self.sourcePort=p1TCP.dst_port
        self.destinationPort=p1TCP.src_port

        '''
        marker=None
        for i in inPacket:
            tcph=i.TCP_header
            flag=tcph.flags
            if flag["RST"]==1:
                self.state[2]=1
            if flag["SYN"]==1:
                if self.state[0]==0:
                    self.startTime=round(i.timestamp,6)
                self.state[0]+=1
            if flag["FIN"]==1:
                marker=i
                self.state[1]+=1
                self.complete=True
            s=i.IP_header.src_ip
            d=i.IP_header.dst_ip
            if (self.sourceAddress==s)and(self.destinationAddress==d):
                self.numBytesSRC+=i.getLen()
                self.sent.append(i)
            elif (self.sourceAddress==d)and(self.destinationAddress==s):
                self.numBytesDEST+=i.getLen()
                self.received.append(i)
            self.window_list.append(i.TCP_header.window_size)
        self.numPacketsSRC=len(self.received)
        self.numPacketsDEST=len(self.sent)

        if self.complete:
            self.endTime=marker.timestamp
            self.totalBytes=self.numBytesDEST+self.numBytesSRC
            
            self.totalPackets=len(inPacket)
            self.duration=round(self.endTime-self.startTime,6)
            
            


    def formatResultsHelp(self):
        #print("==============================")
        print("CONNECTION "+str(self.count1))
        print("Source Address "+str(self.sourceAddress)+":")
        print("Destination Address: "+str(self.destinationAddress))
        print("Source Port: "+str(self.sourcePort))
        print("Destination Port: "+str(self.destinationPort))
        if self.state[2]!=0:
            print("State: S"+str(self.state[0])+"F"+str(self.state[1])+"/R")
        else:
            print("State: S"+str(self.state[0])+"F"+str(self.state[1]))
        #self.complete=True
        if self.complete is True:
            print("Start Time (seconds): "+str(self.startTime))
            print("End Time (seconds): "+str(self.endTime))
            print("Duration (seconds): "+str(self.duration))
            print("Packets from source to destination: "+str(self.numPacketsSRC))
            print("Packets from destination to source: "+str(self.numPacketsDEST))
            print("Total packets: "+str(self.totalPackets))
            print("Bytes count from source to destination: "+str(self.numBytesSRC))
            print("Bytes count from destination to source: "+str(self.numBytesDEST))
            print("Total number of data bytes: "+str(self.totalBytes))
        print("++++++++++++++++++++++++++++")


    def __str__(self):
        return str(self.__class__)+": "+str(self.__dict__)

        
