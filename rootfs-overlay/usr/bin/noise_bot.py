#!/usr/bin/env python3
"""Low-rate deterministic legitimate traffic from five simulated clients."""
import os, socket, sys, time
sys.path.insert(0,"/usr/lib/snort-lab")
from scenario import identity, noise_addresses, stage3_decoy
DEFENDER="10.0.0.10"
def configure(addresses):
    while os.system("ip link show eth0 >/dev/null 2>&1")!=0: time.sleep(1)
    os.system("ip link set eth0 up && ip addr flush dev eth0")
    for address in addresses: os.system("ip addr add %s/24 dev eth0"%address)
def udp(source,port,payload):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind((source,0)); sock.sendto(payload,(DEFENDER,port)); sock.close()
def http(source,port,path,user_agent):
    try:
        sock=socket.socket(); sock.settimeout(2); sock.bind((source,0)); sock.connect((DEFENDER,port))
        sock.sendall(("GET %s HTTP/1.1\r\nHost: defender.local\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n"%(path,user_agent)).encode()); sock.close()
    except OSError: pass
def main():
    email,date,code=identity(); addresses=noise_addresses(); configure(addresses); decoy_port,partial_marker=stage3_decoy()
    print("[*] Benign clients for exercise %s: %s"%(code,", ".join(addresses)))
    sequence=0
    while True:
        udp(addresses[0],53,("DNS query %d example.test"%sequence).encode())
        udp(addresses[1],123,("NTP health %d"%sequence).encode())
        http(addresses[2],80,"/index.html","Mozilla/5.0 PolyLab-Browser")
        http(addresses[3],84,"/health","curl/8.4 PolyLab-Monitor")
        http(addresses[4],8080,"/api/status","PolyLab-Service/1.0")
        udp(addresses[1],decoy_port,b"partial:"+partial_marker+b":decoy")
        sequence+=1; time.sleep(3)
if __name__=="__main__": main()
