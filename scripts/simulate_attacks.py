import time
import socket
import random
import os
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

def simulate_brute_force(target_ip, port=22, attempts=50):
    print(f"{Fore.YELLOW}[*] Simulating Brute Force attack on {target_ip}:{port}...{Style.RESET_ALL}")
    for i in range(attempts):
        try:
            # We just create connections rapidly to simulate brute force connection spam
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target_ip, port))
            s.close()
            print(f"  Attempt {i+1}/{attempts} - Connection made.", end="\r")
        except:
            pass
    print(f"\n{Fore.GREEN}[+] Brute Force simulation complete.{Style.RESET_ALL}")

def simulate_dns_tunneling(target_dns="8.8.8.8"):
    print(f"{Fore.YELLOW}[*] Simulating DNS Tunneling/DGA to {target_dns}...{Style.RESET_ALL}")
    import string
    
    # Generate high entropy subdomain
    for i in range(10):
        entropy_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=30))
        fake_domain = f"{entropy_string}.badactor.com"
        try:
            socket.gethostbyname(fake_domain)
        except:
            pass
        print(f"  Querying: {fake_domain}", end="\r")
        time.sleep(0.5)
    print(f"\n{Fore.GREEN}[+] DNS Tunneling simulation complete.{Style.RESET_ALL}")

def simulate_cryptojacking():
    print(f"{Fore.YELLOW}[*] Simulating Cryptojacking (High CPU load for 10 seconds)...{Style.RESET_ALL}")
    timeout = time.time() + 10
    while time.time() < timeout:
        # Meaningless math to stress CPU
        _ = [x**2 for x in range(10000)]
    print(f"{Fore.GREEN}[+] Cryptojacking simulation complete.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Khandaq Attack Simulator")
    parser.add_argument("--bruteforce", action="store_true", help="Simulate SSH Brute Force")
    parser.add_argument("--dns", action="store_true", help="Simulate DNS Tunneling")
    parser.add_argument("--crypto", action="store_true", help="Simulate Cryptojacking")
    parser.add_argument("--target", type=str, default="127.0.0.1", help="Target IP for network attacks")
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}=== Khandaq SOC Attack Simulator ==={Style.RESET_ALL}\n")
    
    if args.bruteforce:
        simulate_brute_force(args.target)
    if args.dns:
        simulate_dns_tunneling()
    if args.crypto:
        simulate_cryptojacking()
        
    if not (args.bruteforce or args.dns or args.crypto):
        print("Please specify an attack type. Use --help for options.")
        print("Example: python simulate_attacks.py --bruteforce --target 10.0.0.5")

if __name__ == "__main__":
    main()
