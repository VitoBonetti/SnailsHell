# SnailsHell

Network mapping and analysis tool written in Go. 

## Installation

### Prerequisites

  * **Go:** You need Go (version 1.18 or higher) installed on your system. You can download it from [Go's official website](https://golang.org/dl/).
  * **Nmap:** (Optional, but recommended for full functionality) Install Nmap if you plan to use its scanning capabilities. Visit [Nmap.org](https://nmap.org/download.html) for installation instructions.
  * **Wireshark/Npcap (for Windows):** For live packet capture on Windows, you might need to install Npcap (usually bundled with Wireshark).

### Building from Source

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/VitoBonetti/SnailsHell.git
    cd SnailsHell
    ```
2.  **Build the Application:**
    ```bash
    go build -o snailshell .
    ```
    This command will create an executable file named `snailshell` (or `snailshell.exe` on Windows) in your project directory.

    Or simply run the application

    ```bash
    go run .
    ```

## Basic Usage

You can run `snailshell` with or without its web UI, and perform various operations via command-line flags.

### Running the Web UI (Default)

To start the web server and open the UI in your browser:

```bash
./snailshell
```

The application will typically be accessible at `http://localhost:8080/`.

### Command-Line Interface (CLI) Examples

Here are some common operations you can perform from the command line:

  * **List all campaigns:**
    ```bash
    ./snailshell -list
    ```
  * **Start a live packet capture on an interface (e.g., `eth0` or interface index `5`)**
    (Replace `eth0` with your network interface name or index. You can run `./snailshell -live` to see available interfaces):
    ```bash
    ./snailshell -campaign "My Live Scan" -live -iface eth0
    ```
    Or by index:
    ```bash
    ./snailshell -campaign "My Live Scan" -live -iface 5
    ```
  * **Run an Nmap scan on a target:**
    ```bash
    ./snailshell -campaign "My Nmap Scan" -nmap "192.168.1.0/24"
    ```
  * **Process data from files in a directory:**
    ```bash
    ./snailshell -campaign "Imported Data" -dir "./path/to/my/scan/files"
    ```
  * **Compare two campaigns (by name or ID):**
    ```bash
    ./snailshell -compare "Old Scan,New Scan"
    # Or by ID:
    ./snailshell -compare "1,2"
    ```
  * **Open a specific campaign in the web UI:**
    ```bash
    ./snailshell -open "My Live Scan"
    # Or by ID:
    ./snailshell -open-id 1
    ```
  * **Run a CLI command without launching the web UI:**
    (Append `-no-ui` to any command that would normally launch the UI)
    ```bash
    ./snailshell -campaign "My Nmap Scan" -nmap "192.168.1.0/24" -no-ui
    ```

## Standalone Releases

Pre-compiled standalone binaries for various operating systems are available on the GitHub releases page. Download the appropriate file for your system, extract it, and you can run the executable directly without needing to install Go.

Find the latest releases here: [snailshell Releases](https://github.com/VitoBonetti/SnailsHell/releases)