from flask import Flask, render_template_string, request, redirect, url_for, send_file
import os
import io
import pandas as pd
from analyzer import LogAnalyzer
import matplotlib.pyplot as plt

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

TEMPLATE = '''
<!doctype html>
<title>Log File Analyzer</title>
<h1>Log File Analyzer for Intrusion Detection</h1>
<form method=post enctype=multipart/form-data>
  <label>Apache Log File: <input type=file name=apache_log></label><br>
  <label>SSH Log File: <input type=file name=ssh_log></label><br>
  <input type=submit value=Analyze>
</form>
{% if alerts %}
  <h2>Alerts</h2>
  <table border=1>
    <tr><th>Type</th><th>IP</th><th>Count</th><th>Start</th><th>End</th></tr>
    {% for alert in alerts %}
      <tr>
        <td>{{alert['type']}}</td>
        <td>{{alert['ip']}}</td>
        <td>{{alert['count']}}</td>
        <td>{{alert['start']}}</td>
        <td>{{alert['end']}}</td>
      </tr>
    {% endfor %}
  </table>
  <a href="{{url_for('download_report')}}">Download Report (CSV)</a>
  <h2>Top IPs</h2>
  <ul>
    {% for ip, count in top_ips.items() %}
      <li>{{ip}}: {{count}}</li>
    {% endfor %}
  </ul>
  <h2>Requests Over Time (Apache)</h2>
  <img src="{{url_for('plot_apache')}}" alt="Apache Time Series">
  <h2>Requests Over Time (SSH)</h2>
  <img src="{{url_for('plot_ssh')}}" alt="SSH Time Series">
{% endif %}
'''

analyzer = LogAnalyzer()
last_alerts = []
last_top_ips = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    global last_alerts, last_top_ips
    alerts = []
    top_ips = {}
    if request.method == 'POST':
        apache_log = request.files.get('apache_log')
        ssh_log = request.files.get('ssh_log')
        apache_content = apache_log.read().decode() if apache_log and apache_log.filename else None
        ssh_content = ssh_log.read().decode() if ssh_log and ssh_log.filename else None
        analyzer.load_logs(apache_content, ssh_content)
        analyzer.alerts = []
        analyzer.detect_bruteforce()
        analyzer.detect_scanning()
        analyzer.detect_dos()
        alerts = analyzer.get_alerts()
        top_ips = analyzer.get_top_ips().to_dict() if hasattr(analyzer.get_top_ips(), 'to_dict') else {}
        last_alerts = alerts
        last_top_ips = top_ips
    else:
        alerts = last_alerts
        top_ips = last_top_ips
    return render_template_string(TEMPLATE, alerts=alerts, top_ips=top_ips)

@app.route('/download_report')
def download_report():
    if not last_alerts:
        return redirect(url_for('index'))
    df = pd.DataFrame(last_alerts)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(io.BytesIO(buf.read().encode()), mimetype='text/csv', as_attachment=True, download_name='alerts_report.csv')

@app.route('/plot_apache')
def plot_apache():
    ts = analyzer.get_time_series('apache')
    fig, ax = plt.subplots()
    ts.plot(ax=ax)
    ax.set_title('Apache Requests Over Time')
    ax.set_xlabel('Time')
    ax.set_ylabel('Requests')
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    plt.close(fig)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/plot_ssh')
def plot_ssh():
    ts = analyzer.get_time_series('ssh')
    fig, ax = plt.subplots()
    ts.plot(ax=ax)
    ax.set_title('SSH Requests Over Time')
    ax.set_xlabel('Time')
    ax.set_ylabel('Requests')
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    plt.close(fig)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True) 