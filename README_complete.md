CICIDS2017 Complete Feature Extractor
Extract all 78 official CICIDS2017 features from PCAP files with Ground Truth labeling and per-feature computational cost analysis.

🎯 Overview
This tool extracts all 78 official features from the CICIDS2017 dataset specification, designed for comprehensive network intrusion detection research and machine learning model training.
Each feature's computational cost is tracked at nanosecond precision to ensure real-time feasibility on resource-constrained devices.

✨ Features
All 78 Official CICIDS2017 Features
Flow-Based Features (5)

Flow Duration (in microseconds)
Total Forward Packets
Total Backward Packets
Total Length of Forward Packets
Total Length of Backward Packets

Packet Length Statistics (12)
6-9. Forward Packet Length: Min, Max, Mean, Std
10-13. Backward Packet Length: Min, Max, Mean, Std
38-42. Overall Packet Length: Min, Max, Mean, Std, Variance
Flow Rate Features (4)

Flow Bytes/s
Flow Packets/s
Forward Packets/s
Backward Packets/s

Inter-Arrival Time (IAT) Statistics (14)
16-19. Flow IAT: Mean, Std, Max, Min
20-24. Forward IAT: Min, Max, Mean, Std, Total
25-29. Backward IAT: Min, Max, Mean, Std, Total
TCP Flag Features (12)
30-33. Direction-specific: Fwd/Bwd PSH Flags, Fwd/Bwd URG Flags
43-50. Overall Flag Counts: FIN, SYN, RST, PSH, ACK, URG, CWR, ECE
Header Features (2)

Forward Header Length
Backward Header Length

Advanced Features (29)

Down/Up Ratio
Average Packet Size
53-54. Fwd/Bwd Segment Size Average
55-60. Bulk Transfer: Fwd/Bwd Bytes/Packet/Rate Averages
61-64. Subflow: Fwd/Bwd Packets/Bytes
65-66. Init Win Bytes: Fwd/Bwd
Fwd Act Data Packets
Fwd Seg Size Min
69-72. Active: Min, Mean, Max, Std
73-76. Idle: Min, Mean, Max, Std


🚀 Quick Start
Option 1: Download Pre-built EXE (Windows)

Go to Actions tab in GitHub
Click on latest successful workflow run
Download CICIDS2017-Complete-Feature-Extractor artifact
Extract and run CICIDS2017_Complete_Extractor.exe

Option 2: Run from Source
bash# Clone the repository
git clone <your-repo-url>
cd <your-repo>

# Install dependencies
pip install -r requirements.txt

# Run the application
python cicids2017_complete_feature_extractor.py

📊 Output Files
CSV 1: Complete Feature Dataset
Filename: CICIDS2017_78Features_YYYYMMDD_HHMMSS.csv
Contains:

5 Flow identifiers (src_ip, src_port, dst_ip, dst_port, protocol)
78 CICIDS2017 features
Label column (if Ground Truth provided)

Example:
csvsrc_ip,src_port,dst_ip,dst_port,protocol,flow_duration,total_fwd_packets,...,idle_std,label
192.168.1.100,443,10.0.0.5,12345,6,523456,15,...,0.234,DDoS
172.16.0.1,80,10.0.0.10,54321,6,125890,8,...,0.145,BENIGN
CSV 2: Per-Feature Computational Costs
Filename: Feature_Costs_YYYYMMDD_HHMMSS.csv
Contains individual cost for each of the 78 features:

Feature_Name - Name of each feature
Avg_Cost_Microseconds - Average computational cost (μs)
Total_Executions - Number of times calculated
Raspberry_Pi_Status - Performance rating (EXCELLENT/GOOD/ACCEPTABLE/CAUTION)
Estimated_Complexity - Algorithmic complexity (O(1) or O(n))

Example:
csvFeature_Name,Avg_Cost_Microseconds,Total_Executions,Raspberry_Pi_Status,Estimated_Complexity
flow_iat_std,8.234567,1523,GOOD,O(n)
total_fwd_packets,0.125678,1523,EXCELLENT,O(1)
active_mean,4.567890,1523,GOOD,O(n)

🔧 Usage
With Ground Truth (Labeled Dataset)

Launch the application
Select PCAP file using "Browse" button
Select Ground Truth CSV using second "Browse" button
Click "EXTRACT 78 CICIDS2017 FEATURES"
Wait for processing
Output: Features CSV with Label column + Cost CSV

Without Ground Truth (Unlabeled)

Launch the application
Select PCAP file only
Leave Ground Truth field empty
Click "EXTRACT 78 CICIDS2017 FEATURES"
Output: Features CSV (no labels) + Cost CSV


📁 Ground Truth CSV Format
The code automatically detects column names. Supported formats:
Required columns:

Source IP: source_ip, src_ip, source ip, src ip, source_address
Source Port: source_port, src_port, source port, src port
Destination IP: destination_ip, dst_ip, destination ip, dst ip, destination_address
Destination Port: destination_port, dst_port, destination port, dst port
Protocol: protocol, proto
Label: label, attack, attack_type, class, classification

Example CICIDS2017 Ground Truth CSV:
csvSource IP,Source Port,Destination IP,Destination Port,Protocol,Label
192.168.1.100,443,10.0.0.5,12345,6,DDoS
172.16.0.1,80,10.0.0.10,54321,6,BENIGN
10.0.0.50,22,192.168.1.200,55555,6,Brute Force

🧠 Memory Optimization

100 packets max per flow using Python deque(maxlen=100)
Automatic memory management
Suitable for Raspberry Pi 3B+ and Raspberry Pi 4 deployment
Estimated memory usage: 100-300 MB for typical CICIDS2017 files


⚡ Performance
Typical performance on a modern laptop:

Processing Speed: 50,000-100,000 packets/second
Memory Usage: 100-300 MB
Per-Feature Cost: 0.1-10 microseconds per feature
Total Cost (78 features): ~100-500 microseconds per flow


🎓 CICIDS2017 Dataset
This tool is designed for the Canadian Institute for Cybersecurity IDS 2017 dataset:

Traffic Types: BENIGN, DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration, Port Scan, Botnet
Duration: 5 days of network traffic
Instances: ~2.8 million flows
Format: PCAP files + CSV labels

Download: https://www.unb.ca/cic/datasets/ids-2017.html

📈 Feature Categories
CategoryFeaturesComplexityAvg CostFlow Metadata5O(1)< 0.5 μsPacket Length12O(n)1-5 μsFlow Rates4O(1)< 0.5 μsIAT Statistics14O(n)2-10 μsTCP Flags12O(1)< 1 μsHeaders2O(n)1-3 μsAdvanced29Mixed1-8 μs

🛠️ Building Standalone EXE
Automatic Build (GitHub Actions)
The workflow automatically builds on every push to main.
Manual Build
bashpip install pyinstaller
pyinstaller --onefile --console --name "CICIDS2017_Complete_Extractor" --collect-all customtkinter --hidden-import=PIL._tkinter_finder cicids2017_complete_feature_extractor.py
The EXE will be in the dist/ folder.

📚 Feature Descriptions
<details>
<summary>Click to expand full feature list with descriptions</summary>
Flow Features

Flow Duration: Duration of the flow in microseconds
Total Fwd/Bwd Packets: Count of packets in each direction

Packet Length Statistics

Min/Max/Mean/Std: Statistical measures of packet sizes
Variance: Variance in packet length

Inter-Arrival Time (IAT)

Flow/Fwd/Bwd IAT: Time between consecutive packets
Measured in microseconds

TCP Flags

FIN/SYN/RST/PSH/ACK/URG/CWR/ECE: Count of each flag type
Direction-specific PSH and URG flags

Active/Idle Periods

Active: Time flow was active before becoming idle
Idle: Time flow was idle before becoming active
Measured in microseconds

</details>

🐛 Troubleshooting
EXE doesn't open

Extract the ZIP file completely
Right-click EXE → Properties → Unblock
Try running as Administrator
Check Windows Defender didn't quarantine it

"Missing columns" warning

Check your Ground Truth CSV has the required columns
Column names are case-insensitive
The tool will continue without labels if columns are missing

Processing is slow

Large PCAP files (>1GB) may take several minutes
Expected: ~50,000-100,000 packets/second
Consider splitting very large files

Out of memory

Close other applications
Process smaller PCAP files (< 1GB recommended)
Consider increasing virtual memory


📊 Example Workflow
bash# 1. Download CICIDS2017 dataset
wget https://www.unb.ca/cic/datasets/ids-2017.html

# 2. Extract PCAP files
tar -xzf CICIDS2017.tar.gz

# 3. Run extractor
python cicids2017_complete_feature_extractor.py

# 4. Select files in GUI:
#    - PCAP: Monday-WorkingHours.pcap
#    - GT CSV: Monday-WorkingHours.csv

# 5. Output files:
#    - CICIDS2017_78Features_20250107_143025.csv (2.1 MB)
#    - Feature_Costs_20250107_143025.csv (8 KB)

# 6. Use for ML training
python train_model.py --input CICIDS2017_78Features_20250107_143025.csv

📄 Citation
If you use this tool in your research:
bibtex@software{cicids2017_complete_extractor,
  title={CICIDS2017 Complete Feature Extractor},
  author={Your Name},
  year={2025},
  url={https://github.com/your-repo}
}

@inproceedings{sharafaldin2018toward,
  title={Toward generating a new intrusion detection dataset and intrusion traffic characterization},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A},
  booktitle={ICISSP},
  pages={108--116},
  year={2018}
}

📧 Support

Issues: https://github.com/your-repo/issues
Discussions: https://github.com/your-repo/discussions
Email: your.email@example.com


🙏 Acknowledgments

CIC-IDS2017 Dataset - Canadian Institute for Cybersecurity
Scapy - Packet manipulation library
CustomTkinter - Modern GUI framework
Original Paper: Sharafaldin et al. (2018)


📝 License
This project is licensed under the MIT License - see LICENSE file for details.

🔗 Related Projects

CICIDS2017 Dataset: https://www.unb.ca/cic/datasets/ids-2017.html
CICFlowMeter: https://github.com/ISCX/CICFlowMeter
Scapy Documentation: https://scapy.readthedocs.io/


Made with ❤️ for network security research
All 78 official CICIDS2017 features | Ground Truth labeling | Per-feature cost tracking | Raspberry Pi ready
