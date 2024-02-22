# Pcap Analyzer (Network Packet Analyzer)

## Description
Pcap Analyzer is a Python-based tool for analyzing network packet data stored in pcap files. It provides a graphical user interface (GUI) built with Tkinter, allowing users to browse pcap files, analyze packet data, and perform various operations such as viewing packet details, summarizing information, and extracting login passwords from HTTP packets.

## Features
- Browse and select pcap files for analysis.
- Analyze packet data and display it in a table format.
- View detailed information about packets including source and destination addresses, ports, and payload.
- Summarize packet data including counts and unique addresses.
- Extract HTTP login passwords from packet payloads.
- Choose specific columns for displaying in the table.

## Dependencies
- Python 3.x
- Tkinter
- Pandas
- Pandastable
- Scapy
- PIL (Python Imaging Library)

## Installation
1. Clone or download the repository to your local machine.
   ```
   https://github.com/softwarica-github/coursework2-GxbNt.git
   ```
2. Install the required dependencies using pip:
   ```
   pip install -r requirements.txt
   ```
3. Run the `main.py` script:
   ```
   python main.py
   ```

## Usage
1. Launch the application by running the `main.py` script.
2. Use the "Browse" button to select a pcap file for analysis.
3. Click on the "Analyze" button to process the selected pcap file.
4. Once analysis is complete, use the provided buttons to perform various operations such as viewing tables, summarizing data, and extracting login passwords.
5. Explore the different features and functionalities offered by the application.

## Author
- Author: Bishal Ray (@Bishal Ray)
