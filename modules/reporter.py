import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, output_format='terminal'):
        self.format = output_format
        self.report_dir = 'reports'
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def generate(self, results, args):
        """Generate report in specified format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if self.format == 'json':
            return self.generate_json(results, timestamp)
        elif self.format == 'html':
            return self.generate_html(results, timestamp)
        else:
            return self.generate_terminal(results, timestamp)
    
    def generate_json(self, results, timestamp):
        """Generate JSON report"""
        filename = f'{self.report_dir}/scan_{timestamp}.json'
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        return filename
    
    def generate_html(self, results, timestamp):
        """Generate HTML report"""
        filename = f'{self.report_dir}/scan_{timestamp}.html'
        
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .vuln { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #e94560; }
        .safe { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #0f3460; }
        .info { background: #16213e; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .payload { color: #e94560; font-family: monospace; }
        .url { color: #53d769; }
        .timestamp { color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p class="timestamp">Generated: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
    <hr>
'''
        
        for result in results:
            html += f'<h2>Target: <span class="url">{result["url"]}</span></h2>'
            
            # Summary
            total = result['summary']['total_vulnerabilities']
            html += f'<p>Total vulnerabilities found: <strong>{total}</strong></p>'
            
            # XSS Results
            html += '<h3>XSS Vulnerabilities</h3>'
            if result['xss']:
                for v in result['xss']:
                    html += f'''
                    <div class="vuln">
                        <strong>URL:</strong> <span class="url">{v["url"]}</span><br>
                        <strong>Payload:</strong> <span class="payload">{v["payload"]}</span><br>
                        <strong>Type:</strong> {v.get("type", "N/A")}
                    </div>
                    '''
            else:
                html += '<div class="safe">No XSS vulnerabilities detected</div>'
            
            # SQLi Results
            html += '<h3>SQL Injection Vulnerabilities</h3>'
            if result['sqli']:
                for v in result['sqli']:
                    html += f'''
                    <div class="vuln">
                        <strong>URL:</strong> <span class="url">{v["url"]}</span><br>
                        <strong>Payload:</strong> <span class="payload">{v["payload"]}</span><br>
                        <strong>Technique:</strong> {v.get("technique", "N/A")}
                    </div>
                    '''
            else:
                html += '<div class="safe">No SQL injection vulnerabilities detected</div>'
            
            # Recon results
            if result['recon']:
                html += '<h3>Reconnaissance</h3>'
                html += f'<div class="info"><strong>WAF:</strong> {result["recon"].get("waf", "Unknown")}</div>'
                html += f'<div class="info"><strong>Technologies:</strong> {", ".join(result["recon"].get("technologies", []))}</div>'
                if result['recon'].get('subdomains'):
                    html += f'<div class="info"><strong>Subdomains ({len(result["recon"]["subdomains"])}):</strong><br>'
                    html += '<br>'.join(result['recon']['subdomains'][:20])
                    if len(result['recon']['subdomains']) > 20:
                        html += f'<br>...and {len(result["recon"]["subdomains"]) - 20} more'
                    html += '</div>'
            
            html += '<hr>'
        
        html += '</body></html>'
        
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename
    
    def generate_terminal(self, results, timestamp):
        """Just return a timestamp filename"""
        filename = f'{self.report_dir}/scan_{timestamp}.txt'
        return filename