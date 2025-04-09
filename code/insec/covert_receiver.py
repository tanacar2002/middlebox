import socket, os, struct, time, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.all import *
from scapy.layers.inet import IP

KEY = bytes.fromhex(os.getenv('AES_KEY'))

class ICMP:
    _type = 0
    _code = 0
    _checksum = 0
    _comm_id = 0
    _icmp_seq = 0
    _data = b'' #Max Payload 1472 bytes

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

def start_covert_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    covert_server = os.getenv('SECURENET_HOST_IP')
    if not covert_server:
        print("SECURENET_HOST_IP environment variable is not set.")
        return
    bytesReceived = 0
    startTime = time.time()
    while True:
        response, address = sock.recvfrom(4096)
        address = address[0]
        print(f"ICMP from address: {address}")
        if covert_server == address:
            inscapy = IP(response)
            #print(inscapy.show())
            inpacket = ICMP(bytes(inscapy["ICMP"]))
            if inpacket.calcChecksum() == 0:
                #print(inpacket)
                inpacket.decryptData()
                print("Decrypted message:", inpacket.getData())
                bytesReceived += len(inpacket.getData())
                print(f"Avg. throughput: {bytesReceived*8/(time.time()-startTime)/1000:.03f} kbps")

if __name__ == "__main__":
    start_covert_listener()