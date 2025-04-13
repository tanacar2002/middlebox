import os, sys, socket, time, struct, argparse, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.all import *
from scapy.layers.inet import IP
import threading

KEY = bytes.fromhex(os.getenv('AES_KEY'))

sock = None
SEND = []
SENT = []
RESEND = []
ackCount = 0
done = False

class ICMP:
    _type = 0
    _code = 0
    _checksum = 0
    _comm_id = 0
    _icmp_seq = 0
    _data = b'' #Max Payload 1472 bytes, 1471 encrypted bytes + 1 padding byte

    def __init__(self, packetbytes:bytes=b''):
        if len(packetbytes) >= 8:
            self._type, self._code, self._checksum, self._comm_id, self._icmp_seq = struct.unpack("!BBHHH", packetbytes[:8])
            self._data = packetbytes[8:]

    def setType(self, is_request = False):
        if is_request:
            self._type = 8
        else:
            self._type = 0
        self.updateChecksum()

    def setId(self, comm_id):
        self._comm_id = comm_id & 0xFFFF
        self.updateChecksum()

    def getId(self):
        return self._comm_id

    def setSeq(self, icmp_seq):
        self._icmp_seq = icmp_seq & 0xFFFF
        self.updateChecksum()
    
    def getSeq(self):
        return self._icmp_seq

    def setData(self, data):
        self._data = data
        self.updateChecksum()

    def setEncryptedData(self, data):
        h = hashlib.sha3_256()
        h.update(((self._comm_id << 16)+self._icmp_seq).to_bytes(4,byteorder='big'))
        iv = h.digest()
        iv = bytes(a ^ b for a, b in zip(iv[:16], iv[16:]))
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv[:16]))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(data) + padder.finalize()
        self._data =  encryptor.update(padded_message) + encryptor.finalize()
        self.updateChecksum()

    def decryptData(self):
        h = hashlib.sha3_256()
        h.update(((self._comm_id << 16)+self._icmp_seq).to_bytes(4,byteorder='big'))
        iv = h.digest()
        iv = bytes(a ^ b for a, b in zip(iv[:16], iv[16:]))
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded = decryptor.update(self._data) + decryptor.finalize()
        
        self._data = unpadder.update(decrypted_padded) + unpadder.finalize()
        self.updateChecksum()

    def getData(self):
        return self._data

    def getPacket(self, ignoreChksum = False):
        tmpChksum = 0 if ignoreChksum else self._checksum
        return struct.pack("!BBHHH", self._type, self._code, tmpChksum, self._comm_id, self._icmp_seq) + self._data

    def calcChecksum(self, ignoreChksum=False):
        packet = self.getPacket(ignoreChksum)

        if len(packet)%2 != 0:
            packet += b'\0'
        
        checksum = 0
        for i in range(0, len(packet), 2):
            checksum += (packet[i] << 8) + packet[i+1]
            if checksum > 0xffff:
                checksum = (checksum >> 16) + (checksum & 0xffff)
        return (~checksum) & 0xffff
    
    def updateChecksum(self):
        self._checksum = self.calcChecksum(True)
    
    def __str__(self):
        return f"[ICMP]\n\rtype: {self._type}\n\rid: {self._comm_id}\n\rseq: {self._icmp_seq}\n\rdata: {self._data}"

def covert_sender(address:str, verbose:int, noAck):
    if not address:
        print("INSECURENET_HOST_IP environment variable is not set.")
        return
    
    while not done:
        # Send message to the server
        if SEND:
            toBeSent = SEND.pop(0)
            sock.sendto(toBeSent.getPacket(), (address, 0))
            if not noAck:
                SENT.append((toBeSent, time.time()))
            if verbose:
                print(f"Message {toBeSent.getSeq()} sent to {address}")

def covert_ack(address:str, verbose:int):
    global ackCount
    if not address:
        print("INSECURENET_HOST_IP environment variable is not set.")
        return
    while not done:
        response, server = sock.recvfrom(4096)
        server = server[0]
        if server == address:
            inscapy = IP(response)
            #print(inscapy.show())
            inpacket = ICMP(bytes(inscapy["ICMP"]))
            if inpacket.calcChecksum() == 0:
                for idx in range(len(SENT)-1, -1, -1):
                    if SENT[idx][0].getSeq() == inpacket.getSeq():
                        SENT.pop(idx)
                        ackCount += 1
                        break
                if verbose:
                    print(f"Ping Echo {inpacket.getSeq()} received")
                if verbose > 1:
                    print(inpacket)
        for idx in range(len(SENT)-1,-1,-1):
            if time.time()-SENT[idx][1] > 0.7:
                SEND.append(SENT.pop(idx)[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser("covert_sender.py", description="Sends covert ICMP packets, encrypted with AES256.")
    parser.add_argument("-s","--size", 
                        help="size of message in bytes, in the packet it will be converted to upper multiple of 32 bytes, default is the message length, maximum is 1471 bytes",
                        metavar="size",
                        type=int)
    parser.add_argument("-i","--interval", 
                        help="seconds between sending each packet",
                        default=1.0,
                        metavar="interval",
                        type=float)
    parser.add_argument("-d","--duration", 
                        help="seconds of duration of the program, default is infinite",
                        default=float('inf'),
                        metavar="duration",
                        type=float)
    parser.add_argument("-m","--message", 
                        help="string message to be sent",
                        default='Hello from sec! ',
                        metavar="msg",
                        type=str)
    parser.add_argument("-b","--buffersize", 
                        help="max amount messages to be buffered",
                        default=64,
                        metavar="size",
                        type=int)
    parser.add_argument("-t","--resendtime", 
                        help="amount of time waited for echo packet before resending",
                        default=1.0,
                        metavar="time",
                        type=float)
    parser.add_argument("-n","--noAck", 
                        help="to disable the acknowledgement mechanism",
                        action="store_true")
    parser.add_argument("-v","--verbose", 
                        action="count", 
                        default=0,
                        help="increase output verbosity")
    args = parser.parse_args()
    if args.size:
        size = min(args.size, 1471)
    else:
        size = min(len(args.message), 1471)
    proxy = os.getenv('INSECURENET_HOST_IP')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        xSender = threading.Thread(target=covert_sender, args=(proxy, args.verbose, args.noAck), daemon=True)
        xACK = threading.Thread(target=covert_ack, args=(proxy, args.verbose), daemon=True)
        xSender.start()
        if not args.noAck:
            xACK.start()
        i = 0
        msg = args.message.encode()
        msg = msg * ((1472 + len(msg) - 1) // len(msg)) # max payload size is 1472 bytes
        startTime = time.time()
        while not done:
            outpacket = ICMP()
            outpacket.setId(519)
            outpacket.setType(True)
            outpacket.setSeq(i)
            outpacket.setEncryptedData(msg[:size])
            SEND.append(outpacket)
            if time.time() - startTime > args.duration:
                done = True
                break
            while len(SENT) > args.buffersize and not args.noAck:
                if time.time() - startTime > args.duration:
                    done = True
                    break
            i += 1
            time.sleep(args.interval)
        xSender.join()
        if not args.noAck:
            xACK.join()
    except KeyboardInterrupt as e:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        endTime = time.time()
        print(f"Time elapsed: {endTime - startTime:.03f} seconds")
        if args.noAck:
            print(f"Transmitted data: {i * size} bytes")
            print(f"Average throughput: {(i * size * 8 / (endTime - startTime)) / 1000:.03f} kbps")
        else:
            print(f"Acked transmitted data: {ackCount * size} bytes")
            print(f"Average throughput: {(ackCount * size * 8 / (endTime - startTime)) / 1000:.03f} kbps")
        sock.close()
    #covert_sender(args.message.encode(), size, args.interval, args.verbose)