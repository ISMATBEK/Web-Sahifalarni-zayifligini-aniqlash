from flask import Flask, render_template, request, jsonify, send_file
import requests
import os
import json
from datetime import datetime
import tempfile
from urllib.parse import urlparse
import ssl
import socket
from bs4 import BeautifulSoup
import dns.resolver
import urllib3
import re
import time
import logging

# SSL warninglarini o'chirish
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Log konfiguratsiyasi
logging.basicConfig(level=logging.INFO, format='🎬 %(asctime)s - %(message)s')

# DNS resolver sozlamalari
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-scanner-hollywood-pro-2024'

# Tillar lug'ati
TRANSLATIONS = {
    'uz': {
        'title': 'CyberGuard Pro',
        'hero_title': 'KIBER XAVFSIZLIK SKANERI',
        'hero_description': 'Hollywood-style Web Sayt Xavfsizlik Tahlili',
        'scan_placeholder': 'example.com',
        'scan_button': 'SKANERLASHNI BOSHLASH',
        'scanning_title': 'SAYT SKANERLANMOQDA',
        'scanning_subtitle': 'Tizim saytning xavfsizlik tahlilini amalga oshirmoqda...',
        'results_title': 'SKANERLASH NATIJALARI',
        'vulnerabilities': 'ANiQLANGAN ZAiFLiKLAR',
        'security_level': 'XAVFSiZLiK DARAJASI',
        'download_pdf': 'PDF HISOBOT',
        'scan_again': 'YANA SKANERLASH',
        'critical': 'KRiTiK',
        'high': 'YUQORI',
        'medium': "O'RTACHA",
        'low': 'PAST',
        'info': 'MA\'LUMOT'
    },
    'en': {
        'title': 'CyberGuard Pro',
        'hero_title': 'CYBERSECURITY SCANNER',
        'hero_description': 'Hollywood-style Website Security Analysis',
        'scan_placeholder': 'example.com',
        'scan_button': 'START SCANNING',
        'scanning_title': 'SCANNING WEBSITE',
        'scanning_subtitle': 'System is performing security analysis...',
        'results_title': 'SCAN RESULTS',
        'vulnerabilities': 'DETECTED VULNERABILITIES',
        'security_level': 'SECURITY LEVEL',
        'download_pdf': 'PDF REPORT',
        'scan_again': 'SCAN AGAIN',
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO'
    },
    'ru': {
        'title': 'CyberGuard Pro',
        'hero_title': 'СКАНЕР КИБЕРБЕЗОПАСНОСТИ',
        'hero_description': 'Голливудский анализ безопасности сайтов',
        'scan_placeholder': 'example.com',
        'scan_button': 'НАЧАТЬ СКАНИРОВАНИЕ',
        'scanning_title': 'СКАНИРОВАНИЕ САЙТА',
        'scanning_subtitle': 'Система выполняет анализ безопасности...',
        'results_title': 'РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ',
        'vulnerabilities': 'ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ',
        'security_level': 'УРОВЕНЬ БЕЗОПАСНОСТИ',
        'download_pdf': 'PDF ОТЧЕТ',
        'scan_again': 'СКАНИРОВАТЬ СНОВА',
        'critical': 'КРИТИЧЕСКИЙ',
        'high': 'ВЫСОКИЙ',
        'medium': 'СРЕДНИЙ',
        'low': 'НИЗКИЙ',
        'info': 'ИНФО'
    }
}


class LightweightSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {
            'vulnerabilities': [],
            'server_info': {},
            'security_headers': {},
            'response_time': 0,
            'risk_score': 0,
            'security_score': 100,
            'recommendations': []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def safe_request(self, url, timeout=10):
        """Xavfsiz so'rov funksiyasi"""
        try:
            response = self.session.get(url, timeout=timeout, verify=False)
            return response
        except Exception as e:
            print(f"So'rov xatosi {url}: {e}")
            return None

    def scan(self):
        """Soddalashtirilgan skanerlash funksiyasi"""
        try:
            print(f"🔍 Skanerlash boshlandi: {self.target_url}")

            # URL ni to'g'rilash
            parsed_url = urlparse(self.target_url)
            if not parsed_url.scheme:
                self.target_url = 'https://' + self.target_url

            # Asosiy vazifalar
            self.scan_main_website()
            self.analyze_security_headers()
            self.scan_vulnerabilities()
            self.calculate_scores()
            self.generate_recommendations()

            print(f"✅ Skanerlash yakunlandi. {len(self.results['vulnerabilities'])} ta zaiflik topildi.")
            return True

        except Exception as e:
            print(f"❌ Skanerlash xatosi: {e}")
            self.results['error'] = str(e)
            return False

    def scan_main_website(self):
        """Asosiy saytni tekshirish"""
        try:
            start_time = time.time()
            response = self.safe_request(self.target_url, timeout=15)
            end_time = time.time()

            if response is None:
                self.add_vulnerability(
                    'Saytga Ulanish Muammosi',
                    'critical',
                    'Saytga ulanib bo\'lmadi',
                    'Sayt mavjudligini tekshiring',
                    40,
                    'connection_error'
                )
                return

            self.results['response_time'] = round(end_time - start_time, 2)
            self.results['server_info'] = {
                'server': response.headers.get('Server', 'Noma\'lum'),
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', 'Noma\'lum')
            }

            if response.status_code != 200:
                self.add_vulnerability(
                    'Saytga Kirish Muammosi',
                    'high',
                    f'Sayt {response.status_code} status kodi bilan javob berdi',
                    'Sayt mavjudligini tekshiring',
                    20,
                    'site_access'
                )

            self.html_content = response.text
            self.soup = BeautifulSoup(response.content, 'html.parser')

        except Exception as e:
            print(f"Sayt tekshirish xatosi: {e}")

    def analyze_security_headers(self):
        """Xavfsizlik headerlarini tahlil qilish"""
        security_headers = {
            'X-Frame-Options': None,
            'X-Content-Type-Options': None,
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'X-XSS-Protection': None
        }

        try:
            response = self.safe_request(self.target_url, timeout=10)
            if response is None:
                return

            for header in security_headers.keys():
                security_headers[header] = response.headers.get(header)

            self.results['security_headers'] = security_headers

            # Headerlarni tekshirish
            if not security_headers['X-Frame-Options']:
                self.add_vulnerability(
                    'X-Frame-Options Headeri Yo\'q',
                    'medium',
                    'Clickjacking hujumlariga qarshi himoya yo\'q',
                    'X-Frame-Options: SAMEORIGIN headerni qo\'shing',
                    25,
                    'missing_xframe'
                )

            if not security_headers['Content-Security-Policy']:
                self.add_vulnerability(
                    'Content-Security-Policy Yo\'q',
                    'high',
                    'XSS hujumlariga qarshi himoya cheklangan',
                    'Content-Security-Policy headerni qo\'shing',
                    30,
                    'missing_csp'
                )

        except Exception as e:
            print(f"Header tahlili xatosi: {e}")

    def scan_vulnerabilities(self):
        """Zaifliklarni skanerlash"""
        if not hasattr(self, 'soup') or self.soup is None:
            return

        self.check_sensitive_files()
        self.check_information_disclosure()

    def check_sensitive_files(self):
        """Himoyalangan fayllarni tekshirish"""
        sensitive_files = ['robots.txt', '.env', 'admin.php', 'phpinfo.php']
        base_url = self.target_url.rstrip('/')

        for file in sensitive_files:
            try:
                test_url = f"{base_url}/{file}"
                response = self.safe_request(test_url, timeout=5)

                if response and response.status_code == 200:
                    self.add_vulnerability(
                        f'Himoyalangan Fayl Ochiq: {file}',
                        'high',
                        f'Himoyalangan fayl ochiq holatda topildi: {file}',
                        f'{file} faylini himoyalang',
                        35,
                        f'sensitive_file_{file}'
                    )
            except Exception as e:
                continue

    def check_information_disclosure(self):
        """Ma'lumotlar sizib chiqishini tekshirish"""
        server = self.results['server_info'].get('server', '')
        if server and server != 'Noma\'lum':
            self.add_vulnerability(
                'Server Versiyasi Oshkor Qilingan',
                'low',
                f'Server versiyasi oshkor qilingan: {server}',
                'Server headerini yashiring',
                10,
                'server_info_disclosure'
            )

    def add_vulnerability(self, type, severity, description, solution, risk_score, key):
        """Zaiflik qo'shish"""
        self.results['vulnerabilities'].append({
            'type': type,
            'severity': severity,
            'description': description,
            'solution': solution,
            'risk_score': risk_score,
            'id': f"VULN-{len(self.results['vulnerabilities']) + 1:03d}",
            'key': key,
            'icon': self.get_severity_icon(severity)
        })

    def get_severity_icon(self, severity):
        """Severity bo'yicha icon"""
        icons = {
            'critical': '💀',
            'high': '🔥',
            'medium': '⚠️',
            'low': '🔶',
            'info': 'ℹ️'
        }
        return icons.get(severity, '🔍')

    def calculate_scores(self):
        """Xavf va xavfsizlik ballarini hisoblash"""
        try:
            total_risk = sum(vuln.get('risk_score', 0) for vuln in self.results['vulnerabilities'])
            self.results['risk_score'] = min(total_risk, 100)
            self.results['security_score'] = max(100 - total_risk, 0)
        except Exception as e:
            print(f"Score calculation xatosi: {e}")

    def generate_recommendations(self):
        """Tavsiyalar generatsiya qilish"""
        recommendations = []
        vulns = self.results['vulnerabilities']

        if any(v['severity'] == 'critical' for v in vulns):
            recommendations.append("Darvozabon darajadagi zaifliklarni darhol bartaraf eting")

        if any(v['severity'] == 'high' for v in vulns):
            recommendations.append("Yuqori darajadagi xavflarni birinchi navbatda hal qiling")

        if any('ssl' in v['key'] for v in vulns):
            recommendations.append("SSL sertifikatini yangilang va HTTPS ni majburiy qiling")

        if not recommendations:
            recommendations.append("Sayt xavfsizlik jihatdan yaxshi holatda. Muntazam monitoringni davom ettiring")

        self.results['recommendations'] = recommendations


@app.route('/')
def index():
    language = request.args.get('lang', 'uz')
    return render_template('index.html',
                           t=TRANSLATIONS[language],
                           current_language=language)


@app.route('/scan', methods=['POST'])
def scan_website():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'})

        target_url = data.get('url', '').strip()
        if not target_url:
            return jsonify({'success': False, 'error': 'URL kiritilmagan'})

        print(f"🎬 Skanerlash boshlandi: {target_url}")

        # Lightweight scanner ishlatish
        scanner = LightweightSecurityScanner(target_url)
        success = scanner.scan()

        if success:
            response_data = {
                'success': True,
                'results': scanner.results,
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target_url': target_url,
                'scan_id': f"SCAN-{int(time.time())}"
            }
            return jsonify(response_data)
        else:
            return jsonify({'success': False, 'error': scanner.results.get('error', 'Noma\'lum xatolik')})

    except Exception as e:
        print(f"❌ Route error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'})

        results = data.get('results', {})
        scan_date = data.get('scan_date', '')
        target_url = data.get('target_url', '')

        # Soddalashtirilgan HTML hisobot
        html_content = create_simple_report(results, scan_date, target_url)

        # HTML fayl sifatida qaytarish
        html_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix='.html',
            mode='w',
            encoding='utf-8'
        )
        html_file.write(html_content)
        html_file.close()

        return send_file(
            html_file.name,
            as_attachment=True,
            download_name=f'cyberguard_report_{int(time.time())}.html',
            mimetype='text/html'
        )

    except Exception as e:
        print(f"❌ HTML yaratish xatosi: {e}")
        return jsonify({'success': False, 'error': str(e)})


def create_simple_report(results, scan_date, target_url):
    """Soddalashtirilgan HTML hisobot"""
    try:
        vulnerabilities = results.get('vulnerabilities', [])
        security_score = results.get('security_score', 0)
        risk_score = results.get('risk_score', 0)

        vulnerabilities_html = ""
        for vuln in vulnerabilities:
            severity_color = {
                'critical': '#ff003c',
                'high': '#ff6b00',
                'medium': '#ffc107',
                'low': '#00ff41',
                'info': '#007bff'
            }.get(vuln['severity'], '#666')

            vulnerabilities_html += f"""
            <div style="border-left: 5px solid {severity_color}; background: #f8f9fa; padding: 15px; margin: 10px 0;">
                <h3 style="color: {severity_color}; margin: 0;">{vuln['icon']} {vuln['type']}</h3>
                <p><strong>Tavsif:</strong> {vuln['description']}</p>
                <p><strong>Yechim:</strong> {vuln['solution']}</p>
            </div>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>CyberGuard Pro - Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ text-align: center; background: #0a0a0a; color: white; padding: 30px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚀 CYBERGUARD PRO</h1>
                <h2>Security Scan Report</h2>
            </div>

            <div style="margin: 20px 0;">
                <h3>📊 Skanerlash Ma'lumotlari</h3>
                <p><strong>Sayt:</strong> {target_url}</p>
                <p><strong>Sana:</strong> {scan_date}</p>
                <p><strong>Xavfsizlik Darajasi:</strong> {security_score}/100</p>
                <p><strong>Xavf Darajasi:</strong> {risk_score}/100</p>
            </div>

            <h3>🔍 Aniqlangan Zaifliklar ({len(vulnerabilities)})</h3>
            {vulnerabilities_html}

            <div style="margin-top: 40px; text-align: center; color: #666;">
                <p>Generated by CyberGuard Pro</p>
            </div>
        </body>
        </html>
        """
        return html_content

    except Exception as e:
        return f"<html><body><h1>Xatolik: {e}</h1></body></html>"


# Vercel uchun required
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
else:
    # Vercel production uchun
    app = app
