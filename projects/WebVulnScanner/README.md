# Web Application Vulnerability Scanner

## Objective
Build a scanner to detect common web app vulnerabilities like XSS, SQLi, CSRF.

## Features
- Crawls web applications and follows internal links
- Detects XSS, SQL Injection, and missing CSRF tokens in forms
- Uses multiple payloads for advanced detection
- Flask web interface for easy scanning and results viewing
- Results table with evidence and severity

## Tools
- Python 3.7+
- requests
- BeautifulSoup
- Flask

## Setup
1. Clone this repository:
   ```bash
   Clone This Repo &
   cd WebVulnScanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```
4. Open your browser and go to [http://localhost:5000/](http://localhost:5000/)

## Usage
- Enter the target URL in the form and start the scan.
- View results for each form found, including XSS, SQLi, and CSRF status.

 
## License

MIT 
