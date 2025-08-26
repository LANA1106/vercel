import re
import pandas as pd
from datetime import datetime, timedelta

class LogAnalyzer:
    def __init__(self):
        self.df = pd.DataFrame()
        self.alerts = []

    def parse_apache_log(self, log_content):
        # Common Apache log format: 127.0.0.1 - - [date] "GET /path HTTP/1.1" 200 2326
        pattern = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)')
        rows = []
        for line in log_content.splitlines():
            m = pattern.match(line)
            if m:
                dt = datetime.strptime(m.group('datetime').split()[0], '%d/%b/%Y:%H:%M:%S')
                rows.append({
                    'ip': m.group('ip'),
                    'datetime': dt,
                    'method': m.group('method'),
                    'url': m.group('url'),
                    'status': int(m.group('status')),
                    'size': int(m.group('size')),
                    'type': 'apache'
                })
        return pd.DataFrame(rows)

    def parse_ssh_log(self, log_content):
        # Example: Jan  1 12:34:56 server sshd[12345]: Failed password for root from 192.168.1.1 port 22 ssh2
        pattern = re.compile(r'(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) [^ ]+ sshd\[\d+\]: (?P<msg>.+) from (?P<ip>\d+\.\d+\.\d+\.\d+)')
        rows = []
        for line in log_content.splitlines():
            m = pattern.search(line)
            if m:
                # Assume current year
                dt = datetime.strptime(f"{datetime.now().year} {m.group('month')} {m.group('day')} {m.group('time')}", '%Y %b %d %H:%M:%S')
                rows.append({
                    'ip': m.group('ip'),
                    'datetime': dt,
                    'msg': m.group('msg'),
                    'type': 'ssh'
                })
        return pd.DataFrame(rows)

    def load_logs(self, apache_log=None, ssh_log=None):
        dfs = []
        if apache_log:
            dfs.append(self.parse_apache_log(apache_log))
        if ssh_log:
            dfs.append(self.parse_ssh_log(ssh_log))
        if dfs:
            self.df = pd.concat(dfs, ignore_index=True)
        else:
            self.df = pd.DataFrame()

    def detect_bruteforce(self, threshold=5, window_minutes=5):
        # SSH: Many failed logins from same IP in short time
        if self.df.empty:
            return []
        ssh_df = self.df[self.df['type'] == 'ssh']
        if ssh_df.empty:
            return []
        failed = ssh_df[ssh_df['msg'].str.contains('Failed password', na=False)]
        failed = failed.sort_values('datetime')
        alerts = []
        for ip, group in failed.groupby('ip'):
            times = group['datetime'].tolist()
            for i in range(len(times) - threshold + 1):
                if (times[i + threshold - 1] - times[i]) <= timedelta(minutes=window_minutes):
                    alerts.append({'type': 'Brute-force', 'ip': ip, 'count': threshold, 'start': times[i], 'end': times[i + threshold - 1]})
                    break
        self.alerts.extend(alerts)
        return alerts

    def detect_scanning(self, threshold=10, window_minutes=5):
        # Apache: Many different URLs from same IP in short time
        if self.df.empty:
            return []
        apache_df = self.df[self.df['type'] == 'apache']
        if apache_df.empty:
            return []
        alerts = []
        for ip, group in apache_df.groupby('ip'):
            group = group.sort_values('datetime')
            for i in range(len(group) - threshold + 1):
                window = group.iloc[i:i+threshold]
                if (window['datetime'].iloc[-1] - window['datetime'].iloc[0]) <= timedelta(minutes=window_minutes):
                    if window['url'].nunique() >= threshold:
                        alerts.append({'type': 'Scanning', 'ip': ip, 'count': threshold, 'start': window['datetime'].iloc[0], 'end': window['datetime'].iloc[-1]})
                        break
        self.alerts.extend(alerts)
        return alerts

    def detect_dos(self, threshold=100, window_minutes=1):
        # Apache: High request rate from same IP
        if self.df.empty:
            return []
        apache_df = self.df[self.df['type'] == 'apache']
        if apache_df.empty:
            return []
        alerts = []
        for ip, group in apache_df.groupby('ip'):
            group = group.sort_values('datetime')
            for i in range(len(group) - threshold + 1):
                window = group.iloc[i:i+threshold]
                if (window['datetime'].iloc[-1] - window['datetime'].iloc[0]) <= timedelta(minutes=window_minutes):
                    alerts.append({'type': 'DoS', 'ip': ip, 'count': threshold, 'start': window['datetime'].iloc[0], 'end': window['datetime'].iloc[-1]})
                    break
        self.alerts.extend(alerts)
        return alerts

    def get_alerts(self):
        return self.alerts

    def export_alerts(self, path):
        pd.DataFrame(self.alerts).to_csv(path, index=False)

    def get_top_ips(self, n=10):
        if self.df.empty:
            return []
        return self.df['ip'].value_counts().head(n)

    def get_time_series(self, log_type='apache'):
        if self.df.empty:
            return pd.Series()
        df = self.df[self.df['type'] == log_type]
        if df.empty:
            return pd.Series()
        return df.set_index('datetime').resample('1T').size() 