import asyncio
from nats.aio.client import Client as NATS
import os, random, sys
from scapy.all import Ether
from covert_detector import covertDetector

REQUEST = 8
REPLY = 0

# https://www.ibm.com/docs/en/aix/7.1.0?topic=channels-bandwidth-guidelines
BUCKET_SIZE = 10 # burst in bytes
buckets = {}
pktCount = 0
droppedCount = 0

async def run():
    nc = NATS()

    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        global pktCount, droppedCount
        subject = msg.subject
        data = msg.data #.decode()
        # print(f"Received a message on '{subject}': {data}")
        packet = Ether(data)
        # print(packet.show())
        drop = False
        
        if packet.haslayer("IP"):
            if packet.haslayer("ICMP"):
                if packet["ICMP"].getfieldval("type") == REQUEST:
                    pktCount += 1
            # Drop if fragmented, according to RFC 8900
            if packet["IP"].getfieldval("frag") > 0 or int(packet["IP"].getfieldval("flags")) & 1:
                drop = True # This can also be specialized for ICMP packets
            else:
                srcip = packet["IP"].getfieldval("src") #str
                dstip = packet["IP"].getfieldval("dst") #str
                if covertDetector(packet):
                    drop = True
                    # if srcip not in buckets.keys():
                    #     buckets[srcip] = len(packet["Raw"].getfieldval("load"))
                    # else:
                    #     buckets[srcip] += len(packet["Raw"].getfieldval("load"))
                    # if dstip not in buckets.keys():
                    #     buckets[dstip] = len(packet["Raw"].getfieldval("load"))
                    # else:
                    #     buckets[dstip] += len(packet["Raw"].getfieldval("load"))
        if not drop:
            if subject == "inpktsec":
                await nc.publish("outpktinsec", msg.data)
            else:
                await nc.publish("outpktsec", msg.data)
        else:
            droppedCount += 1
            print("DROPPED")
   
    # Subscribe to inpktsec and inpktinsec topics
    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            for key in buckets.keys():
                if buckets[key] > 0:
                    buckets[key] -= 1
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print(f"\nInspected {pktCount} ICMP Request packets.")
        print(f"Dropped {droppedCount} packets.")