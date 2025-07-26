# Portscanner

Portscanner is a command-line tool written in Go that automates port scanning to identify open ports and their associated services/versions on a list of IP addresses. It uses `masscan` to quickly discover open ports and `nmap` for service and version detection, producing a formatted output in the format `[IP:port] [service] [details]`. The tool is designed for efficiency, processing XML outputs with embedded XSLT transformations using `xsltproc`.

## Features
- **Fast Port Discovery**: Uses `masscan` to scan all ports (0–65535) at a high rate.
- **Service Detection**: Uses `nmap` with `--version-light` to identify services and versions running on open ports, minimizing scan time.
- **Customizable Input/Output**: Accepts an input file with IPs and writes results to a specified output file.
- **Embedded XSLT**: Processes `masscan` and `nmap` XML outputs with embedded XSLT for consistent formatting, eliminating external file dependencies.
- **Error Handling**: Robust checks for file existence, command execution, and output validation, with clear error messages and warnings.

## Requirements
- **Go**: Version 1.22 or later (for module support and stable `os` package).
- **System Tools**:
  - `masscan`: For initial port scanning (requires root privileges).
  - `nmap`: For service and version detection.
  - `xsltproc`: For processing XML outputs with XSLT.
- **System Dependencies**:
  - `libxml2-dev` and `libxslt1-dev` (required for `xsltproc`).
- **Permissions**: Write access to the output directory and `sudo` access for `masscan`.

## Installation
1. **Install Go**:
   ```bash
   sudo apt-get install golang
   ```
   Verify:
   ```bash
   go version
   ```

2. **Install System Dependencies**:
   ```bash
   sudo apt-get install masscan nmap xsltproc libxml2-dev libxslt1-dev
   ```

3. **Clone or Create the Project**:
   Place the `portscanner.go` file in a directory (e.g., `/home/hacker/Desktop/portscanner/`).

4. **Initialize Go Module**:
   ```bash
   cd /home/hacker/Desktop/portscanner/
   go mod init portscanner
   go mod tidy
   ```

5. **Build the Tool**:
   ```bash
   go build -o portscanner .
   ```

## 💾 Persistent Installation

### System-wide (all users):
```bash
sudo mv portscanner /usr/local/bin/
```
### Single user (current user only):
```bash
mv portscanner ~/.local/bin/
```
> Note: For single-user installs, ensure ~/.local/bin is in your $PATH.
 
## Usage
Run the tool with the `-i` and `-o` flags to specify the input and output files:
```bash
./portscanner -i <input_file> -o <output_file>
```
- `-i <input_file>`: Path to a text file containing IP addresses (one per line).
- `-o <output_file>`: Path to the output file for scan results.

### Example
1. Create an `ips.txt` file:
   ```bash
   echo -e "17.253.144.10\n41.78.18.49" > ips.txt
   ```

2. Run the tool:
   ```bash
   ./portscanner -i ips.txt -o scan_results.txt
   ```

3. Expected output in `scan_results.txt`:
   ```
   [17.253.144.10:80] [http] []
   [17.253.144.10:443] [https] []
   [41.78.18.49:80] [http] [nginx]
   [41.78.18.49:443] [http] [nginx]
   ```


## Configuration
- **Input File Format**: A text file with one IP address per line (e.g., `ips.txt`).
- **Output Format**: Results are written in the format `[IP:port] [service] [details]`, where `details` includes the service product, version, and extra info (if available).
- **Sudo for Masscan**: The tool uses `sudo masscan`.

## Notes
- **Performance**: The tool uses `masscan` for fast port discovery and `nmap` with `--version-light` for efficient service detection, minimizing scan time.
- **XSLT Processing**: Uses `xsltproc` for stable and reliable XML transformations, with XSLT embedded in the program to avoid external file dependencies.
- **Legal Notice**: Ensure you have permission to scan the target IPs. Unauthorized scanning may violate laws or terms of service.
- **File Permissions**: Ensure write permissions in the output directory (e.g., `/home/hacker/Desktop/portscanner/`):


## Troubleshooting
1. **Verify Dependencies**:
   ```bash
   masscan --version
   nmap --version
   xsltproc --version
   ```
   Install missing tools:
   ```bash
   sudo apt-get install masscan nmap xsltproc
   ```

2. **Debug Output**:
   Run with redirected output to capture errors:
   ```bash
   ./portscanner -i ips.txt -o scan_results.txt > output.log 2>&1
   cat output.log
   ```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details
## Contributing
Contributions are welcome! Please submit issues or pull requests to the project repository (if hosted on a platform like GitHub).
