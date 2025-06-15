from scapy.all import Ether
import time, struct

REQUEST = 8
REPLY = 0

TIMEOUT_THRESHOLD = 2 * 1_000_000_000 # Maximum allowed late Reply message arrival time in nanoseconds
CHECK_TIMESTAMP = True # Whether to check timeval in Linux messages
SECS_THRESHOLD = 1500 # Allowed drift in timeval value from processor system time (+-25 hours for local time differences and additional clock drift)
LOW_PERIOD_CHECK_THRESHOLD = 320_000_000
HIGH_PERIOD_CHECK_THRESHOLD = 32_000_000_000
IPDV_THRESHOLD = 32_000_000

echoReplyMatch = {}
lastReceivedTS = {}

def covertDetector(packet: Ether):
    """
    Covert channel detector for ICMP echo/reply packets utilizing payload field.

    """
    TS = time.monotonic_ns()
    host_nsecs = time.time_ns()
    if packet.haslayer("ICMP"):
        if packet.haslayer("Raw"): # If packet does not have payload, it doesn't concern us
            # Request Reply ID matching: No reply packet can be sent before requested
            payload = packet["Raw"].getfieldval("load")
            if packet["ICMP"].getfieldval("type") == REQUEST:
                srcip = packet["IP"].getfieldval("src")
                query = srcip + str(packet["ICMP"].getfieldval("id")) + str(packet["ICMP"].getfieldval("seq"))
                echoReplyMatch[query] = (payload, TS)

                # Windows ping payload matching
                win_match = True
                for i,b in enumerate(payload):
                    if (int(b)-0x61) % 0x17 != i:
                        win_match = False
                if win_match and (len(payload) == 32):
                    return False
                # Linux Mac ip-utils ping payload matching
                if len(payload) != 56: # To prevent message length covert information
                    return True
                if len(payload) < 16:
                    for i,b in enumerate(payload):
                        if int(b) != i:
                            return True
                else:
                    secs, usecs = struct.unpack("<qq", payload[:16])
                    timeval_ns = secs * 1_000_000_000 + usecs * 1000
                    print("Secs:", secs, "\t", "Msecs:", usecs)
                    host_secs = host_nsecs // 1_000_000_000
                    host_usecs = (host_nsecs % 1_000_000_000) // 1000
                    print("HOST Secs:", host_secs, "\t", "Msecs:", host_usecs)
                    if CHECK_TIMESTAMP:
                        if usecs >= 1_000_000 or usecs < 0: # At least 44 bits should be 0
                            return True
                        if abs(host_secs - secs) > SECS_THRESHOLD: # timeval correctness check, assuming the host syns with NTP
                            return True
                        if srcip not in lastReceivedTS:
                            lastReceivedTS[srcip] = (timeval_ns, TS)
                        elif (TS - lastReceivedTS[srcip][1]) > HIGH_PERIOD_CHECK_THRESHOLD: # Don't check for messages with very high periodicity and reset (lower than 0.1 bits/s covert capability)
                            lastReceivedTS[srcip] = (timeval_ns, TS)
                        elif (TS - lastReceivedTS[srcip][1]) < LOW_PERIOD_CHECK_THRESHOLD: # Don't allow for messages with very low periodicity and reset (Higher than 100 bits/s covert capability)
                            lastReceivedTS[srcip] = (timeval_ns, TS)
                            return True
                        else:
                            last_timeval_ns, lastTS = lastReceivedTS[srcip]
                            IPDV = (TS - lastTS) - (timeval_ns - last_timeval_ns)
                            lastReceivedTS[srcip] = (timeval_ns, TS)
                            if abs(IPDV) > IPDV_THRESHOLD: # Don't allow sudden changes in period
                                return True
                    for i, b in enumerate(payload):
                        if (i > 15) and (int(b) != i % 256):
                            return True
            
            elif packet["ICMP"].getfieldval("type") == REPLY:
                query = packet["IP"].getfieldval("dst") + str(packet["ICMP"].getfieldval("id")) + str(packet["ICMP"].getfieldval("seq"))
                if query in echoReplyMatch.keys():
                    reqPayload, reqTS = echoReplyMatch.pop(query)
                    respTime = TS - reqTS
                    if payload != reqPayload:
                        print("Reply Payload doesn't match with Request!")
                        return True
                    if respTime > TIMEOUT_THRESHOLD:
                        print(f"Reply came {respTime}s late!")
                        return True
                else:
                    return True
            
    return False