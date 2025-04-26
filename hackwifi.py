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
    
    def reset_interface(self):
        """Reset interface to managed mode"""
        if self.interface:
            print(f"{Fore.YELLOW}[*] Resetting interface {self.interface}...{Style.RESET_ALL}")
            try:
                subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], check=False)
                subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'managed'], check=False)
                subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], check=False)
                print(f"{Fore.GREEN}[+] Interface {self.interface} reset to managed mode{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error resetting interface: {e}{Style.RESET_ALL}")
    
    def get_available_interfaces(self):
        """Get list of available wireless interfaces"""
        interfaces = []
        try:
            # Check for wireless interfaces
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = [line.split()[0] for line in result.stdout.split('\n') 
                         if 'IEEE 802.11' in line and not line.startswith(' ')]
            
            # Alternative method if iwconfig fails
            if not interfaces:
                interfaces = [iface for iface in os.listdir('/sys/class/net') 
                            if iface.startswith('w')]
        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting interfaces: {e}{Style.RESET_ALL}")
        
        return interfaces
    
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
    
    def select_interface(self):
        """Select and configure wireless interface"""
        while True:
            interfaces = self.get_available_interfaces()
            
            if not interfaces:
                print(f"{Fore.RED}[!] No wireless interfaces found!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Try:{Style.RESET_ALL}")
                print("1. Re-plug your WiFi adapter")
                print("2. Run: sudo airmon-ng check kill")
                print("3. Check with 'iwconfig'")
                choice = input("\nPress Enter to retry or 'q' to quit: ")
                if choice.lower() == 'q':
                    sys.exit(1)
                continue
            
            print(f"{Fore.YELLOW}[*] Available interfaces:{Style.RESET_ALL}")
            for i, iface in enumerate(interfaces):
                print(f"{i+1}. {iface}")
            
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
        
        # Kill conflicting processes
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL)
        
        commands = [
            ['ifconfig', self.interface, 'down'],
            ['iwconfig', self.interface, 'mode', 'monitor'],
            ['ifconfig', self.interface, 'up']
        ]
        
        for cmd in commands:
            try:
                subprocess.run(['sudo'] + cmd, check=True)
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[!] Failed to configure interface: {e}{Style.RESET_ALL}")
                self.reset_interface()
                sys.exit(1)
        
        print(f"{Fore.GREEN}[+] {self.interface} ready in monitor mode{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        if self.running:
            print(f"\n{Fore.YELLOW}[*] Stopping scan...{Style.RESET_ALL}")
            self.running = False
        elif self.deauth_running:
            print(f"\n{Fore.YELLOW}[*] Stopping attack...{Style.RESET_ALL}")
            self.deauth_running = False
        else:
            self.reset_interface()
            print(f"\n{Fore.GREEN}[+] Exiting{Style.RESET_ALL}")
            sys.exit(0)

    # [Rest of your existing methods remain unchanged...]

if __name__ == "__main__":
    # Verify root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Requires root privileges!{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = WiFiHackingTool()
    try:
        tool.select_interface()
        tool.scan_wifi()
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        tool.reset_interface()
        sys.exit(1)
