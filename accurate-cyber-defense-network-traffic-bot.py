#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Accurate Cyber Defense Network Traffic Bot - v1.0

A command-line tool for network monitoring and traffic generation with Telegram integration.
"""

import os
import sys
import socket
import threading
import time
import subprocess
import platform
import argparse
import json
import requests
from datetime import datetime
import random
import dns.resolver
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore, Style

# Initialize colorama
init()
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

# Configuration
CONFIG_FILE = "bot_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "traffic_generation": {
        "default_port": 80,
        "default_packet_size": 64,
        "default_duration": 10
    },
    "monitoring": {
        "interval": 5,
        "timeout": 2
    }
}

class CyberSecurityBot:
    def __init__(self):
        self.running = True
        self.config = self.load_config()
        self.traffic_thread = None
        self.monitor_thread = None
        self.stop_traffic = threading.Event()
        self.stop_monitoring = threading.Event()
        self.current_action = None
        
        # Red theme setup
        self.banner_color = RED
        self.command_color = YELLOW
        self.text_color = WHITE
        self.error_color = RED
        self.success_color = GREEN
        self.info_color = CYAN
        
        self.print_banner()
        
    def print_banner(self):
        """Display the red-themed banner"""
        banner = f"""
        {self.banner_color}
         ____       _                     _____           _       _   
     
        {self.text_color} Accurate Cyber Defense Network Traffic Bot v16.0{RESET}
        {self.text_color}Type 'help' for available commands{RESET}
        """
        print(banner)
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with default config to ensure all keys exist
                    for key in DEFAULT_CONFIG:
                        if key not in config:
                            config[key] = DEFAULT_CONFIG[key]
                    return config
            except Exception as e:
                print(f"{RED}Error loading config: {e}{RESET}")
                return DEFAULT_CONFIG
        else:
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG
    
    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            print(f"{RED}Error saving config: {e}{RESET}")
            return False
    
    def send_telegram_message(self, message):
        """Send message to Telegram chat"""
        if not self.config['telegram_token'] or not self.config['telegram_chat_id']:
            return False
        
        url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
        payload = {
            'chat_id': self.config['telegram_chat_id'],
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        try:
            response = requests.post(url, data=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"{RED}Telegram API error: {e}{RESET}")
            return False
    
    def ping(self, ip_address):
        """Ping an IP address"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip_address]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            message = f"Ping results for {ip_address}:\n{output}"
            print(f"{self.info_color}{message}{RESET}")
            self.send_telegram_message(f"```\n{message}\n```")
            return True
        except subprocess.CalledProcessError as e:
            error = f"Ping failed for {ip_address}: {e.output}"
            print(f"{self.error_color}{error}{RESET}")
            self.send_telegram_message(f"Ping failed for {ip_address}")
            return False
    
    def traceroute(self, ip_address):
        """Perform traceroute to an IP address"""
        try:
            param = '-d' if platform.system().lower() == 'windows' else ''
            command = ['tracert', param, ip_address] if platform.system().lower() == 'windows' else ['traceroute', ip_address]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            message = f"Traceroute to {ip_address}:\n{output}"
            print(f"{self.info_color}{message}{RESET}")
            self.send_telegram_message(f"```\n{message}\n```")
            return True
        except subprocess.CalledProcessError as e:
            error = f"Traceroute failed for {ip_address}: {e.output}"
            print(f"{self.error_color}{error}{RESET}")
            self.send_telegram_message(f"Traceroute failed for {ip_address}")
            return False
    
    def nslookup(self, ip_address):
        """Perform DNS lookup for an IP address or domain"""
        try:
            result = dns.resolver.resolve(ip_address, 'A')
            output = f"DNS lookup for {ip_address}:\n"
            for ipval in result:
                output += f"IP: {ipval.to_text()}\n"
            
            message = output
            print(f"{self.info_color}{message}{RESET}")
            self.send_telegram_message(f"```\n{message}\n```")
            return True
        except Exception as e:
            error = f"DNS lookup failed for {ip_address}: {str(e)}"
            print(f"{self.error_color}{error}{RESET}")
            self.send_telegram_message(f"DNS lookup failed for {ip_address}")
            return False
    
    def port_scan(self, ip_address, ports=None):
        """Scan ports on a target IP address"""
        try:
            if ports is None:
                ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
            
            open_ports = []
            output = f"Scanning {ip_address}...\n"
            
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    output += f"Port {port}: {GREEN}OPEN{RESET}\n"
                    open_ports.append(port)
                else:
                    output += f"Port {port}: {RED}CLOSED{RESET}\n"
            
            message = f"Port scan results for {ip_address}:\n{output}"
            print(f"{self.info_color}{message}{RESET}")
            self.send_telegram_message(f"```\nPort scan results for {ip_address}:\nOpen ports: {open_ports}\n```")
            return True
        except Exception as e:
            error = f"Port scan failed for {ip_address}: {str(e)}"
            print(f"{self.error_color}{error}{RESET}")
            self.send_telegram_message(f"Port scan failed for {ip_address}")
            return False
    
    def generate_traffic(self, ip_address, port=None, packet_size=None, duration=None):
        """Generate network traffic to a specific IP and port"""
        if port is None:
            port = self.config['traffic_generation']['default_port']
        if packet_size is None:
            packet_size = self.config['traffic_generation']['default_packet_size']
        if duration is None:
            duration = self.config['traffic_generation']['default_duration']
        
        self.stop_traffic.clear()
        self.traffic_thread = threading.Thread(
            target=self._traffic_worker,
            args=(ip_address, port, packet_size, duration)
        )
        self.traffic_thread.start()
        
        message = f"Started generating traffic to {ip_address}:{port} for {duration} seconds"
        print(f"{self.info_color}{message}{RESET}")
        self.send_telegram_message(message)
        return True
    
    def _traffic_worker(self, ip_address, port, packet_size, duration):
        """Worker function for traffic generation"""
        start_time = time.time()
        packet_count = 0
        
        try:
            while not self.stop_traffic.is_set() and (time.time() - start_time) < duration:
                # Randomize source port
                src_port = random.randint(1024, 65535)
                
                # Create and send packet
                packet = IP(dst=ip_address)/TCP(sport=src_port, dport=port)/("X"*packet_size)
                scapy.send(packet, verbose=0)
                
                packet_count += 1
                time.sleep(0.1)  # Throttle to avoid flooding
                
            message = f"Generated {packet_count} packets to {ip_address}:{port}"
            print(f"{self.success_color}{message}{RESET}")
            self.send_telegram_message(message)
        except Exception as e:
            error = f"Traffic generation error: {str(e)}"
            print(f"{self.error_color}{error}{RESET}")
            self.send_telegram_message(f"Traffic generation failed for {ip_address}:{port}")
    
    def stop_traffic_generation(self):
        """Stop generating traffic"""
        if self.traffic_thread and self.traffic_thread.is_alive():
            self.stop_traffic.set()
            self.traffic_thread.join()
            message = "Stopped traffic generation"
            print(f"{self.success_color}{message}{RESET}")
            self.send_telegram_message(message)
            return True
        else:
            message = "No active traffic generation to stop"
            print(f"{self.error_color}{message}{RESET}")
            return False
    
    def start_monitoring(self, ip_address):
        """Start monitoring an IP address"""
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(ip_address,)
        )
        self.monitor_thread.start()
        
        message = f"Started monitoring {ip_address}"
        print(f"{self.info_color}{message}{RESET}")
        self.send_telegram_message(message)
        return True
    
    def _monitoring_worker(self, ip_address):
        """Worker function for monitoring"""
        interval = self.config['monitoring']['interval']
        timeout = self.config['monitoring']['timeout']
        
        while not self.stop_monitoring.is_set():
            status = "OFFLINE"
            color = RED
            
            try:
                # Try to connect to common port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, 80))
                sock.close()
                
                if result == 0:
                    status = "ONLINE"
                    color = GREEN
            except:
                pass
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"[{timestamp}] {ip_address} status: {color}{status}{RESET}"
            print(message)
            
            if status == "OFFLINE":
                self.send_telegram_message(f"⚠️ {ip_address} is offline at {timestamp}")
            
            time.sleep(interval)
    
    def stop_monitoring_ip(self):
        """Stop monitoring an IP address"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.stop_monitoring.set()
            self.monitor_thread.join()
            message = "Stopped monitoring"
            print(f"{self.success_color}{message}{RESET}")
            self.send_telegram_message(message)
            return True
        else:
            message = "No active monitoring to stop"
            print(f"{self.error_color}{message}{RESET}")
            return False
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        return True
    
    def show_help(self):
        """Display help information"""
        help_text = f"""
        {self.command_color}Available Commands:{RESET}
        
        {self.command_color}help{RESET} - Show this help message
        {self.command_color}exit{RESET} - Exit the bot
        {self.command_color}clear{RESET} - Clear the screen
        
        {self.command_color}ping <ip_address>{RESET} - Ping an IP address
        {self.command_color}tracert <ip_address>{RESET} - Perform traceroute to an IP address
        {self.command_color}nslookup <ip_address>{RESET} - Perform DNS lookup for an IP/domain
        {self.command_color}scan <ip_address>{RESET} - Scan common ports on an IP address
        
        {self.command_color}generate_traffic <ip_address> [port] [packet_size] [duration]{RESET} - Generate network traffic
        {self.command_color}stop{RESET} - Stop traffic generation or monitoring
        
        {self.command_color}start_monitoring <ip_address>{RESET} - Start monitoring an IP address
        {self.command_color}stop_monitoring{RESET} - Stop monitoring
        
        {self.command_color}config{RESET} - Show current configuration
        {self.command_color}set_config <key> <value>{RESET} - Update configuration
        """
        print(help_text)
        return True
    
    def show_config(self):
        """Display current configuration"""
        config_str = json.dumps(self.config, indent=4)
        print(f"{self.info_color}Current Configuration:{RESET}\n{config_str}")
        return True
    
    def set_config(self, key, value):
        """Update configuration setting"""
        keys = key.split('.')
        current = self.config
        
        try:
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            
            # Try to convert value to appropriate type
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    if value.lower() in ('true', 'false'):
                        value = value.lower() == 'true'
            
            current[keys[-1]] = value
            self.save_config(self.config)
            
            message = f"Configuration updated: {key} = {value}"
            print(f"{self.success_color}{message}{RESET}")
            self.send_telegram_message(message)
            return True
        except Exception as e:
            error = f"Failed to update configuration: {str(e)}"
            print(f"{self.error_color}{error}{RESET}")
            return False
    
    def process_command(self, command):
        """Process user command"""
        if not command.strip():
            return True
        
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == 'help':
                return self.show_help()
            elif cmd == 'exit':
                self.running = False
                print(f"{self.info_color}Exiting...{RESET}")
                return True
            elif cmd == 'clear':
                return self.clear_screen()
            elif cmd == 'ping' and len(args) >= 1:
                return self.ping(args[0])
            elif cmd == 'tracert' and len(args) >= 1:
                return self.traceroute(args[0])
            elif cmd == 'nslookup' and len(args) >= 1:
                return self.nslookup(args[0])
            elif cmd == 'scan' and len(args) >= 1:
                ports = None
                if len(args) > 1:
                    ports = [int(p) for p in args[1].split(',')]
                return self.port_scan(args[0], ports)
            elif cmd == 'generate_traffic' and len(args) >= 1:
                port = int(args[1]) if len(args) > 1 else None
                packet_size = int(args[2]) if len(args) > 2 else None
                duration = int(args[3]) if len(args) > 3 else None
                return self.generate_traffic(args[0], port, packet_size, duration)
            elif cmd == 'stop':
                if self.current_action == 'traffic':
                    return self.stop_traffic_generation()
                elif self.current_action == 'monitoring':
                    return self.stop_monitoring_ip()
                else:
                    print(f"{self.error_color}No active operation to stop{RESET}")
                    return False
            elif cmd == 'start_monitoring' and len(args) >= 1:
                self.current_action = 'monitoring'
                return self.start_monitoring(args[0])
            elif cmd == 'stop_monitoring':
                self.current_action = None
                return self.stop_monitoring_ip()
            elif cmd == 'config':
                return self.show_config()
            elif cmd == 'set_config' and len(args) >= 2:
                return self.set_config(args[0], ' '.join(args[1:]))
            else:
                print(f"{self.error_color}Unknown command or invalid arguments. Type 'help' for available commands.{RESET}")
                return False
        except Exception as e:
            print(f"{self.error_color}Error executing command: {str(e)}{RESET}")
            return False
    
    def run(self):
        """Main bot loop"""
        while self.running:
            try:
                command = input(f"{self.command_color}cyberbot>{RESET} ").strip()
                self.process_command(command)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the bot")
            except Exception as e:
                print(f"{self.error_color}Error: {str(e)}{RESET}")

def main():
    parser = argparse.ArgumentParser(description='Accurate Cyber Defense Network Traffic Bot')
    parser.add_argument('--config', help='Path to configuration file', default=CONFIG_FILE)
    args = parser.parse_args()
    
    bot = CyberSecurityBot()
    bot.run()

if __name__ == "__main__":
    main()