import os
import subprocess
import requests
import json
import re
from datetime import datetime, timedelta
import time
from packaging import version
import sqlite3
import hashlib
import argparse
import sys
import threading
from tqdm import tqdm

# Database setup for caching
def setup_cache_db():
    """
    Set up SQLite database for caching NVD API responses.
    """
    db_path = os.path.join(os.path.expanduser("~"), ".vulnerability_scanner_cache.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS nvd_cache (
        query_hash TEXT PRIMARY KEY,
        response_data TEXT,
        timestamp DATETIME
    )
    ''')
    
    # Create table for vulnerability data
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerability_data (
        cve_id TEXT PRIMARY KEY,
        data TEXT,
        last_updated DATETIME
    )
    ''')
    
    conn.commit()
    return conn

# Cache NVD API responses
def get_cached_response(query, conn, cache_ttl=24):
    """
    Get cached response for a query or fetch from API if not cached.
    
    Args:
        query: Dictionary containing query parameters
        conn: Database connection
        cache_ttl: Cache time-to-live in hours
        
    Returns:
        API response data
    """
    cursor = conn.cursor()
    
    # Create a hash of the query for cache key
    query_hash = hashlib.md5(json.dumps(query, sort_keys=True).encode()).hexdigest()
    
    # Check if we have a cached response
    cursor.execute(
        "SELECT response_data, timestamp FROM nvd_cache WHERE query_hash = ?", 
        (query_hash,)
    )
    result = cursor.fetchone()
    
    if result:
        response_data, timestamp = result
        cache_time = datetime.fromisoformat(timestamp)
        
        # Check if cache is still valid
        if datetime.now() - cache_time < timedelta(hours=cache_ttl):
            return json.loads(response_data)
    
    # If no valid cache, fetch from API
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    headers = {}
    if "api_key" in query:
        headers["apiKey"] = query.pop("api_key")
    
    try:
        response = requests.get(base_url, params=query, headers=headers)
        
        # Handle rate limiting
        if response.status_code == 403:
            print("Rate limit exceeded. Waiting before retrying...")
            time.sleep(6)
            response = requests.get(base_url, params=query, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Cache the response
            cursor.execute(
                "INSERT OR REPLACE INTO nvd_cache VALUES (?, ?, ?)",
                (query_hash, json.dumps(data), datetime.now().isoformat())
            )
            conn.commit()
            
            return data
        else:
            print(f"API request failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching from API: {str(e)}")
        return None

# Get installed packages from Debian/Ubuntu based systems
def get_installed_packages_debian():
    """
    Get list of installed packages on Debian/Ubuntu systems.
    
    Returns:
        List of dictionaries with package name and version
    """
    try:
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
        packages = []
        
        for line in result.stdout.splitlines():
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    package_name = parts[1]
                    version = parts[2]
                    packages.append({"name": package_name, "version": version})
        
        return packages
    except Exception as e:
        print(f"Error getting Debian packages: {str(e)}")
        return []

# Get installed packages from RedHat/CentOS based systems
def get_installed_packages_redhat():
    """
    Get list of installed packages on RedHat/CentOS systems.
    
    Returns:
        List of dictionaries with package name and version
    """
    try:
        result = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n'], 
                               capture_output=True, text=True)
        packages = []
        
        for line in result.stdout.splitlines():
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    package_name = parts[0]
                    version = parts[1]
                    packages.append({"name": package_name, "version": version})
        
        return packages
    except Exception as e:
        print(f"Error getting RedHat packages: {str(e)}")
        return []

# Get installed packages from Arch Linux systems
def get_installed_packages_arch():
    """
    Get list of installed packages on Arch Linux systems.
    
    Returns:
        List of dictionaries with package name and version
    """
    try:
        result = subprocess.run(['pacman', '-Q'], capture_output=True, text=True)
        packages = []
        
        for line in result.stdout.splitlines():
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    package_name = parts[0]
                    version = parts[1]
                    packages.append({"name": package_name, "version": version})
        
        return packages
    except Exception as e:
        print(f"Error getting Arch packages: {str(e)}")
        return []

# Check if a version is within a vulnerable range
def is_version_in_range(current_version, version_range):
    """
    Check if the current version is within a vulnerable version range.
    Handles various version range formats like:
    - <= 1.2.3 (less than or equal)
    - >= 1.2.3 (greater than or equal)
    - > 1.2.3 (greater than)
    - < 1.2.3 (less than)
    - = 1.2.3 (equal)
    - 1.2.3 (implicit equal)
    - 1.2.3 - 2.0.0 (range between versions)
    """
    try:
        # Clean up the version string to handle packaging version requirements
        current_version = current_version.replace('-', '.')
        
        # Handle version ranges like "1.2.3 - 2.0.0"
        if ' - ' in version_range:
            start, end = version_range.split(' - ')
            return (version.parse(start) <= version.parse(current_version) <= version.parse(end))
        
        # Handle operators
        if version_range.startswith('<='):
            return version.parse(current_version) <= version.parse(version_range[2:].strip())
        elif version_range.startswith('>='):
            return version.parse(current_version) >= version.parse(version_range[2:].strip())
        elif version_range.startswith('<'):
            return version.parse(current_version) < version.parse(version_range[1:].strip())
        elif version_range.startswith('>'):
            return version.parse(current_version) > version.parse(version_range[1:].strip())
        elif version_range.startswith('='):
            return version.parse(current_version) == version.parse(version_range[1:].strip())
        else:
            # Assume exact version match if no operator
            return version.parse(current_version) == version.parse(version_range.strip())
    except Exception as e:
        # If there's any error in parsing, log it and return False
        return False

# Check if a package is vulnerable based on CVE configuration data
def is_vulnerable(configurations, package_name, package_version):
    """
    Determine if a package with specific version is vulnerable based on CVE configuration data.
    
    Args:
        configurations: The configuration nodes from NVD CVE data
        package_name: The name of the package to check
        package_version: The version of the package to check
        
    Returns:
        Boolean indicating if the package is vulnerable
    """
    if not configurations:
        return False
    
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe_match in cpe_matches:
                # Check if this CPE entry is relevant to our package
                cpe23Uri = cpe_match.get("criteria", "")
                
                # Extract product name from CPE URI
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe23Uri.split(':')
                if len(parts) >= 5:
                    cpe_product = parts[4].lower()
                    
                    # Check if the product name matches our package
                    if package_name.lower() in cpe_product or cpe_product in package_name.lower():
                        # Check version ranges
                        vulnerable = True
                        
                        # Check versionStartIncluding
                        if "versionStartIncluding" in cpe_match:
                            start_version = cpe_match["versionStartIncluding"]
                            try:
                                if version.parse(package_version) < version.parse(start_version):
                                    vulnerable = False
                            except:
                                pass
                        
                        # Check versionStartExcluding
                        elif "versionStartExcluding" in cpe_match:
                            start_version = cpe_match["versionStartExcluding"]
                            try:
                                if version.parse(package_version) <= version.parse(start_version):
                                    vulnerable = False
                            except:
                                pass
                        
                        # Check versionEndIncluding
                        if "versionEndIncluding" in cpe_match:
                            end_version = cpe_match["versionEndIncluding"]
                            try:
                                if version.parse(package_version) > version.parse(end_version):
                                    vulnerable = False
                            except:
                                pass
                        
                        # Check versionEndExcluding
                        elif "versionEndExcluding" in cpe_match:
                            end_version = cpe_match["versionEndExcluding"]
                            try:
                                if version.parse(package_version) >= version.parse(end_version):
                                    vulnerable = False
                            except:
                                pass
                        
                        # If the CPE has a specific version, check exact match
                        if parts[5] not in ["*", "-"]:
                            cpe_version = parts[5]
                            if cpe_version != package_version:
                                vulnerable = False
                        
                        if vulnerable and cpe_match.get("vulnerable", True):
                            return True
    
    return False

# Get severity information from CVE data
def get_severity(cve):
    """
    Extract severity information from CVE data.
    
    Args:
        cve: The CVE data object
        
    Returns:
        String representing severity level (CRITICAL, HIGH, MEDIUM, LOW)
    """
    metrics = cve.get("metrics", {})
    
    # Try to get CVSS V3 score first
    cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_v3 and len(cvss_v3) > 0:
        base_severity = cvss_v3[0].get("cvssData", {}).get("baseSeverity")
        if base_severity:
            return base_severity
    
    # Fall back to CVSS V2 if V3 is not available
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2 and len(cvss_v2) > 0:
        base_severity = cvss_v2[0].get("baseSeverity")
        if base_severity:
            return base_severity
        
        # If baseSeverity is not available, calculate from score
        base_score = cvss_v2[0].get("cvssData", {}).get("baseScore")
        if base_score:
            if float(base_score) >= 9.0:
                return "CRITICAL"
            elif float(base_score) >= 7.0:
                return "HIGH"
            elif float(base_score) >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
    
    # Default severity if nothing is found
    return "UNKNOWN"

# Check vulnerabilities for a package using NVD API with caching
def check_vulnerabilities(package_name, package_version, conn, api_key=None):
    """
    Query the NVD API to check for vulnerabilities for a specific package.
    
    Args:
        package_name: Name of the package to check
        package_version: Version of the package to check
        conn: Database connection for caching
        api_key: Optional API key for NVD API
        
    Returns:
        List of vulnerabilities affecting the package
    """
    # Set up query parameters
    query = {
        "keywordSearch": package_name,
        "resultsPerPage": 100
    }
    
    if api_key:
        query["api_key"] = api_key
    
    # Get response from cache or API
    data = get_cached_response(query, conn)
    
    if not data:
        return []
    
    vulnerabilities = []
    
    # Process each vulnerability from the response
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        
        # Get the description in English if available
        description = "No description"
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        
        # Check if the vulnerability affects our package version
        configurations = cve.get("configurations", [])
        if is_vulnerable(configurations, package_name, package_version):
            severity = get_severity(cve)
            published_date = cve.get("published", "Unknown")
            
            # Add the vulnerability to our list
            vulnerabilities.append({
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "published_date": published_date
            })
    
    return vulnerabilities

# Generate notification for vulnerabilities
def generate_notification(vulnerable_packages):
    """
    Generate notifications for vulnerable packages.
    
    Args:
        vulnerable_packages: List of packages with vulnerabilities
        
    Returns:
        String containing notification message
    """
    if not vulnerable_packages:
        return "No vulnerabilities found."
    
    message = f"SECURITY ALERT: {len(vulnerable_packages)} vulnerable packages found on your system.\n\n"
    
    # Group vulnerabilities by severity
    critical = []
    high = []
    medium = []
    low = []
    
    for package in vulnerable_packages:
        for vuln in package.get("vulnerabilities", []):
            severity = vuln.get("severity", "UNKNOWN")
            item = f"{package['name']} (v{package['version']}): {vuln['cve_id']} - {vuln['description'][:100]}..."
            
            if severity == "CRITICAL":
                critical.append(item)
            elif severity == "HIGH":
                high.append(item)
            elif severity == "MEDIUM":
                medium.append(item)
            else:
                low.append(item)
    
    # Add critical vulnerabilities to the message
    if critical:
        message += f"\nCRITICAL VULNERABILITIES ({len(critical)}):\n"
        message += "\n".join([f"- {item}" for item in critical])
    
    # Add high vulnerabilities to the message
    if high:
        message += f"\n\nHIGH VULNERABILITIES ({len(high)}):\n"
        message += "\n".join([f"- {item}" for item in high[:5]])
        if len(high) > 5:
            message += f"\n- ... and {len(high) - 5} more high severity vulnerabilities"
    
    # Add summary of medium and low vulnerabilities
    if medium:
        message += f"\n\nMEDIUM VULNERABILITIES: {len(medium)}"
    if low:
        message += f"\nLOW VULNERABILITIES: {len(low)}"
    
    # Add recommendation
    message += "\n\nRECOMMENDATION: Update your system as soon as possible with:"
    message += "\n- For Debian/Ubuntu: sudo apt update && sudo apt upgrade"
    message += "\n- For RedHat/CentOS: sudo yum update"
    message += "\n- For Arch Linux: sudo pacman -Syu"
    
    return message

# Generate detailed report
def generate_report(vulnerable_packages, output_format="text"):
    """
    Generate a detailed report of vulnerabilities.
    
    Args:
        vulnerable_packages: List of packages with vulnerabilities
        output_format: Format of the report (text or json)
        
    Returns:
        Path to the generated report file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnerability_report_{timestamp}.{output_format}"
    
    if output_format == "text":
        with open(filename, "w") as f:
            f.write(f"Vulnerability Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Found {len(vulnerable_packages)} vulnerable packages\n\n")
            
            for package in vulnerable_packages:
                f.write(f"Package: {package['name']} (Version: {package['version']})\n")
                f.write("-" * 60 + "\n")
                
                for vuln in package["vulnerabilities"]:
                    f.write(f"CVE: {vuln['cve_id']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"Published: {vuln['published_date']}\n")
                    f.write(f"Description: {vuln['description']}\n\n")
                
                f.write("\n")
    elif output_format == "json":
        with open(filename, "w") as f:
            json.dump({
                "scan_date": datetime.now().isoformat(),
                "vulnerable_packages": vulnerable_packages
            }, f, indent=2)
    
    print(f"Report generated: {filename}")
    return filename

# Detect Linux distribution automatically
def detect_linux_distribution():
    """
    Automatically detect the Linux distribution.
    
    Returns:
        String representing the distribution type
    """
    if os.path.exists("/etc/debian_version"):
        return "debian"
    elif os.path.exists("/etc/redhat-release"):
        return "redhat"
    elif os.path.exists("/etc/arch-release"):
        return "arch"
    else:
        return "unknown"

# Interactive OS selection
def select_os_interactively():
    """
    Allow user to select OS interactively.
    
    Returns:
        String representing the selected OS type
    """
    print("\nSelect your Linux distribution:")
    print("1. Debian/Ubuntu")
    print("2. RedHat/CentOS/Fedora")
    print("3. Arch Linux")
    print("4. Auto-detect")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-4): ")
            if choice == "1":
                return "debian"
            elif choice == "2":
                return "redhat"
            elif choice == "3":
                return "arch"
            elif choice == "4":
                detected = detect_linux_distribution()
                if detected == "unknown":
                    print("Could not auto-detect your distribution. Please select manually.")
                else:
                    print(f"Detected {detected} distribution.")
                    return detected
            else:
                print("Invalid choice. Please enter a number between 1 and 4.")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)

# Worker function for parallel scanning
def scan_package_worker(package, conn, api_key, results, lock, progress_bar):
    """
    Worker function to scan a package for vulnerabilities.
    
    Args:
        package: Package to scan
        conn: Database connection
        api_key: NVD API key
        results: Shared results list
        lock: Thread lock for synchronization
        progress_bar: Progress bar to update
    """
    vulnerabilities = check_vulnerabilities(package["name"], package["version"], conn, api_key)
    
    if vulnerabilities:
        package_result = package.copy()
        package_result["vulnerabilities"] = vulnerabilities
        
        with lock:
            results.append(package_result)
    
    # Update progress bar
    progress_bar.update(1)

# Main scanning function with parallel processing
def scan_system(os_type=None, notify=False, min_severity="LOW", api_key=None, threads=4):
    """
    Scan the system for vulnerable packages.
    
    Args:
        os_type: Type of operating system (debian, redhat, arch)
        notify: Whether to generate notifications
        min_severity: Minimum severity level to report
        api_key: API key for NVD API
        threads: Number of parallel threads to use
        
    Returns:
        List of vulnerable packages
    """
    # Set up caching database
    conn = setup_cache_db()
    
    # If OS type is not specified, detect or ask
    if not os_type:
        os_type = select_os_interactively()
    
    # Get installed packages based on OS type
    if os_type == "debian":
        packages = get_installed_packages_debian()
    elif os_type == "redhat":
        packages = get_installed_packages_redhat()
    elif os_type == "arch":
        packages = get_installed_packages_arch()
    else:
        print("Unsupported Linux distribution.")
        return []
    
    print(f"Scanning {len(packages)} packages for vulnerabilities...")
    
    # Set up severity filter
    severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_level = severity_levels.get(min_severity.upper(), 1)
    
    # Use parallel processing for scanning
    vulnerable_packages = []
    lock = threading.Lock()
    
    # Create progress bar
    progress_bar = tqdm(total=len(packages), desc="Scanning packages")
    
    # Process packages in batches to control thread count
    batch_size = min(threads, 10)  # Limit max concurrent threads
    
    for i in range(0, len(packages), batch_size):
        batch = packages[i:i+batch_size]
        threads_list = []
        
        # Create and start threads for this batch
        for package in batch:
            thread = threading.Thread(
                target=scan_package_worker,
                args=(package, conn, api_key, vulnerable_packages, lock, progress_bar)
            )
            threads_list.append(thread)
            thread.start()
        
        # Wait for all threads in this batch to complete
        for thread in threads_list:
            thread.join()
    
    # Close progress bar
    progress_bar.close()
    
    # Filter vulnerabilities by severity
    filtered_packages = []
    for package in vulnerable_packages:
        filtered_vulns = []
        for vuln in package["vulnerabilities"]:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity_levels.get(severity, 0) >= min_level:
                filtered_vulns.append(vuln)
        
        if filtered_vulns:
            package_copy = package.copy()
            package_copy["vulnerabilities"] = filtered_vulns
            filtered_packages.append(package_copy)
    
    # Generate notification if requested
    if notify and filtered_packages:
        notification = generate_notification(filtered_packages)
        print("\n" + notification)
    
    # Print summary
    print(f"\nScan complete. Found {len(filtered_packages)} vulnerable packages with {min_severity} or higher severity.")
    
    return filtered_packages
