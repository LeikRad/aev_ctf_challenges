from scapy.all import *
load_contrib("snmp")
import socket

HOST, PORT = "10.110.3.72", 8024
COMMUNITY  = "public"
BASE       = "1.3.6.1"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

oid = BASE
while True:
    pkt = SNMP(community=COMMUNITY,
               PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
    s.sendto(bytes(pkt), (HOST, PORT))
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        print("timeout"); break
    resp = SNMP(data)
    vb = resp.PDU.varbindlist[0]
    noid = str(vb.oid.val)
    val = vb.value.val if vb.value is not None else None
    if val is None:
        print("NEXT AFTER", oid, "->", noid, "| raw:", bytes(resp).hex())
        break
    if not noid.startswith(BASE):
        print("end ->", noid, val); break
    print(noid, "=", val)
    oid = noid

