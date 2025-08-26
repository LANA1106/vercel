from flask import Flask, render_template, request, redirect, url_for, flash
import os
from scanner import WebVulnScanner

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production

@app.route('/', methods=['GET'])
def index():
    results = request.args.get('results')
    return render_template('index.html', results=results)

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    scanner = WebVulnScanner(url)
    results = scanner.run_all_scans()
    flash(f'Scan started for {url}', 'info')
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True) 