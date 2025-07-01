#!/usr/bin/env python3
import subprocess
import argparse
import sys
import os
import time
import socket
from concurrent.futures import ThreadPoolExecutor

class CrackingTools:
    def __init__(self, timeout=30):
        self.timeout = timeout

    def hashcat_crack(self, hash_file, wordlist, hash_mode, rule_file=None):
        """Run hashcat with specified parameters"""
        print(f"[*] Running hashcat on {hash_file}")
        
        cmd = ["hashcat", "-m", str(hash_mode), hash_file, wordlist]
        
        if rule_file:
            cmd.extend(["-r", rule_file])
        
        cmd.append("--force")
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                print(f"[+] Hashcat completed successfully")
                print(result.stdout)
            else:
                print(f"[-] Hashcat failed with return code {result.returncode}")
                if result.stderr:
                    print(f"Error: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            print(f"[!] Hashcat timed out after {self.timeout} seconds")
        except FileNotFoundError:
            print("[!] Error: hashcat not found. Please install hashcat.")
        except Exception as e:
            print(f"[!] Error running hashcat: {e}")

    def john_crack(self, hash_file, wordlist, rule_name=None):
        """Run John the Ripper with specified parameters"""
        print(f"[*] Running John the Ripper on {hash_file}")
        
        cmd = ["john", f"--wordlist={wordlist}", hash_file]
        
        if rule_name:
            cmd.insert(-1, f"--rules={rule_name}")
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            print(f"[+] John the Ripper output:")
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print(f"[!] John timed out after {self.timeout} seconds")
        except FileNotFoundError:
            print("[!] Error: john not found. Please install john.")
        except Exception as e:
            print(f"[!] Error running john: {e}")

    def hydra_attack(self, target, service, username=None, password=None, userlist=None, passlist=None, port=None):
        """Run Hydra brute force attack"""
        print(f"[*] Running Hydra attack on {target}:{service}")
        
        cmd = ["hydra"]
        
        # Add username/userlist
        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])
        else:
            cmd.extend(["-l", "admin"])  # Default username
        
        # Add password/passlist
        if password:
            cmd.extend(["-p", password])
        elif passlist:
            cmd.extend(["-P", passlist])
        else:
            cmd.extend(["-P", "/usr/share/wordlists/rockyou.txt"])  # Default wordlist
        
        # Add port if specified
        if port:
            cmd.extend(["-s", str(port)])
        
        # Add target and service
        cmd.append(f"{service}://{target}")
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            print(f"[+] Hydra output:")
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print(f"[!] Hydra timed out after {self.timeout} seconds")
        except FileNotFoundError:
            print("[!] Error: hydra not found. Please install hydra.")
        except Exception as e:
            print(f"[!] Error running hydra: {e}")

    def responder_capture(self, interface):
        """Start Responder for hash capture"""
        print(f"[*] Starting Responder on interface {interface}")
        
        cmd = ["responder", "-I", interface]
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            print(f"[*] Responder will capture hashes. Press Ctrl+C to stop.")
            result = subprocess.run(cmd, timeout=self.timeout)
            
        except subprocess.TimeoutExpired:
            print(f"[!] Responder stopped after {self.timeout} seconds")
        except KeyboardInterrupt:
            print(f"[!] Responder stopped by user")
        except FileNotFoundError:
            print("[!] Error: responder not found. Please install responder.")
        except Exception as e:
            print(f"[!] Error running responder: {e}")

    def create_hashcat_rule(self, rule_file, rule_content):
        """Create a custom hashcat rule file"""
        print(f"[*] Creating hashcat rule file: {rule_file}")
        
        try:
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            print(f"[+] Rule file created successfully")
            
        except Exception as e:
            print(f"[-] Error creating rule file: {e}")

    def create_john_rule(self, rule_name, rule_content):
        """Create a custom John the Ripper rule"""
        print(f"[*] Creating John rule: {rule_name}")
        
        john_rule = f"[List.Rules:{rule_name}]\n{rule_content}\n"
        
        try:
            # Try to append to john.conf
            john_conf_paths = [
                "/etc/john/john.conf",
                "/usr/share/john/john.conf",
                "john.conf"  # Local file
            ]
            
            rule_file = f"{rule_name}.rule"
            with open(rule_file, 'w') as f:
                f.write(john_rule)
            
            print(f"[+] John rule created in {rule_file}")
            print(f"[*] To use: john --wordlist=wordlist.txt --rules={rule_name} hash.txt")
            print(f"[*] Or append to john.conf: cat {rule_file} >> /etc/john/john.conf")
            
        except Exception as e:
            print(f"[-] Error creating John rule: {e}")

    def identify_hash_type(self, hash_value):
        """Identify hash type for hashcat mode selection"""
        print(f"[*] Identifying hash type")
        
        hash_types = {
            32: "MD5 (mode 0)",
            40: "SHA1 (mode 100)", 
            64: "SHA256 (mode 1400)",
            128: "SHA512 (mode 1700)",
            "NTLM": "NTLM (mode 1000) - 32 chars",
            "NetNTLMv2": "NetNTLMv2 (mode 5600) - contains ::",
            "bcrypt": "bcrypt (mode 3200) - starts with $2",
            "KeePass": "KeePass (mode 13400) - contains $keepass$"
        }
        
        hash_len = len(hash_value.strip())
        
        print(f"[+] Hash length: {hash_len}")
        
        if "::" in hash_value:
            print(f"[+] Likely NetNTLMv2 hash (hashcat mode 5600)")
        elif "$keepass$" in hash_value:
            print(f"[+] Likely KeePass hash (hashcat mode 13400)")
        elif hash_value.startswith("$2"):
            print(f"[+] Likely bcrypt hash (hashcat mode 3200)")
        elif hash_len in hash_types:
            print(f"[+] Likely {hash_types[hash_len]}")
        else:
            print(f"[-] Unknown hash type")
            
        print(f"[*] Common hashcat modes:")
        print(f"    0 - MD5")
        print(f"    100 - SHA1") 
        print(f"    1000 - NTLM")
        print(f"    1400 - SHA256")
        print(f"    3200 - bcrypt")
        print(f"    5600 - NetNTLMv2")
        print(f"    13400 - KeePass")
        print(f"    22921 - RSA/DSA/EC/OpenSSH Private Keys")

    def generate_common_rules(self):
        """Generate common password mutation rules"""
        print(f"[*] Common password mutation rules")
        
        rules = {
            "Basic": [
                ":",  # No change
                "c",  # Capitalize first letter
                "u",  # Uppercase all
                "l",  # Lowercase all
                "r",  # Reverse
                "d",  # Duplicate
            ],
            "Append Numbers": [
                "$1", "$2", "$3", "$4", "$5",
                "$1$2", "$1$2$3", "$1$3$7"
            ],
            "Append Special": [
                "$!", "$@", "$#", "$%", "$*",
                "$1$!", "$2$@", "$3$#"
            ],
            "Combined": [
                "c $1 $3 $7 $!",  # Capitalize + 137!
                "c $1 $3 $7 $@",  # Capitalize + 137@
                "c $1 $3 $7 $#",  # Capitalize + 137#
            ]
        }
        
        for category, rule_list in rules.items():
            print(f"[+] {category} Rules:")
            for rule in rule_list:
                print(f"    {rule}")

def main():
    parser = argparse.ArgumentParser(description="Password Cracking Tools")
    parser.add_argument("--hashcat", help="Run hashcat (provide hash file)")
    parser.add_argument("--john", help="Run John the Ripper (provide hash file)")
    parser.add_argument("--hydra", help="Run Hydra attack (provide target)")
    parser.add_argument("--responder", help="Start Responder (provide interface)")
    parser.add_argument("--identify-hash", help="Identify hash type")
    parser.add_argument("--create-rule", help="Create rule file (provide filename)")
    parser.add_argument("--show-rules", action="store_true", help="Show common rules")
    
    # Hashcat options
    parser.add_argument("--hash-mode", type=int, default=0, help="Hashcat hash mode")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Wordlist file")
    parser.add_argument("--rule-file", help="Rule file for hashcat")
    
    # John options
    parser.add_argument("--john-rule", help="John rule name")
    
    # Hydra options
    parser.add_argument("--service", default="ssh", help="Service to attack")
    parser.add_argument("--username", help="Single username")
    parser.add_argument("--password", help="Single password")
    parser.add_argument("--userlist", help="Username list file")
    parser.add_argument("--passlist", help="Password list file")
    parser.add_argument("--port", type=int, help="Service port")
    
    parser.add_argument("--timeout", type=int, default=30, help="Command timeout")
    
    args = parser.parse_args()
    
    cracker = CrackingTools(args.timeout)
    
    if args.hashcat:
        cracker.hashcat_crack(args.hashcat, args.wordlist, args.hash_mode, args.rule_file)
    
    elif args.john:
        cracker.john_crack(args.john, args.wordlist, args.john_rule)
    
    elif args.hydra:
        cracker.hydra_attack(args.hydra, args.service, args.username, args.password, 
                           args.userlist, args.passlist, args.port)
    
    elif args.responder:
        cracker.responder_capture(args.responder)
    
    elif args.identify_hash:
        cracker.identify_hash_type(args.identify_hash)
    
    elif args.create_rule:
        rule_content = input("Enter rule content (one rule per line, empty line to finish):\n")
        rules = []
        while True:
            line = input()
            if not line:
                break
            rules.append(line)
        
        if args.john_rule:
            cracker.create_john_rule(args.create_rule, '\n'.join(rules))
        else:
            cracker.create_hashcat_rule(args.create_rule, '\n'.join(rules))
    
    elif args.show_rules:
        cracker.generate_common_rules()
    
    else:
        print("Please specify an action. Use --help for options.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cracking interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)