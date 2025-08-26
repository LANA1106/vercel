# Log File Analyzer for Intrusion Detection

This tool detects suspicious patterns in Apache and SSH logs, such as brute-force attacks, scanning, and DoS. It provides both a command-line and a web interface.

## Features
- Parse Apache and SSH logs
- Detect brute-force, scanning, and DoS patterns
- Visualize access patterns (by IP, time)
- Export incident reports (CSV)
- Web interface for uploading logs and viewing results

## Requirements
- Python 3.8+
- Flask
- pandas
- matplotlib

Install dependencies:
```
pip install -r requirements.txt
```

## Usage

### Web Interface
```
python webapp.py
```
Open your browser to http://127.0.0.1:5000

Upload your Apache and/or SSH log files, view alerts, and download reports.

### CLI (optional)
A CLI interface can be added using the core `analyzer.py` module.

## Sample Logs
Place sample log files in a `sample_logs/` directory for testing.

## Project Structure
- `analyzer.py`: Core logic
- `webapp.py`: Flask web interface
- `requirements.txt`: Dependencies
- `sample_logs/`: Example logs 