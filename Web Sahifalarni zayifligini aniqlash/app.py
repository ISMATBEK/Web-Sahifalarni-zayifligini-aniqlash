from flask import Flask, render_template, request, jsonify, send_file
import requests
import os
import json
import threading
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
import random
import logging
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# SSL warninglarini o'chirish
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Log konfiguratsiyasi
logging.basicConfig(level=logging.INFO, format='🎬 %(asctime)s - %(message)s')

# DNS resolver sozlamalari
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google va Cloudflare DNS

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


class AdvancedSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {
            'vulnerabilities': [],
            'server_info': {},
            'security_headers': {},
            'ssl_info': {},
            'tech_stack': [],
            'response_time': 0,
            'dns_info': {},
            'subdomains': [],
            'risk_score': 0,
            'security_score': 100,
            'recommendations': [],
            'scan_details': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def safe_request(self, url, timeout=10):
        """Xavfsiz so'rov funksiyasi"""
        try:
            response = self.session.get(url, timeout=timeout, verify=False)
            return response
        except requests.exceptions.Timeout:
            print(f"So'rov vaqti tugadi: {url}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"Ulanish xatosi: {url}")
            return None
        except Exception as e:
            print(f"So'rov xatosi {url}: {e}")
            return None

    def scan(self):
        """Asosiy skanerlash funksiyasi"""
        try:
            print(f"🔍 Batafsil skanerlash boshlandi: {self.target_url}")

            # URL ni to'g'rilash
            parsed_url = urlparse(self.target_url)
            if not parsed_url.scheme:
                self.target_url = 'https://' + self.target_url
                parsed_url = urlparse(self.target_url)

            domain = parsed_url.netloc

            # Vazifalarni ketma-ket bajarish
            tasks = [
                self.scan_main_website,
                lambda: self.scan_ssl_certificate(domain),
                lambda: self.scan_dns_records(domain),
                lambda: self.find_subdomains(domain),
                self.analyze_security_headers,
                self.scan_vulnerabilities,
                self.detect_technology_stack
            ]

            for task in tasks:
                try:
                    task()
                except Exception as e:
                    print(f"Vazifa xatosi: {e}")
                    continue

            # Ballarni hisoblash
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
                    'Sayt mavjudligini va tarmoq sozlamalarini tekshiring',
                    40,
                    'connection_error'
                )
                return

            self.results['response_time'] = round(end_time - start_time, 2)
            self.results['server_info'] = {
                'server': response.headers.get('Server', 'Noma\'lum'),
                'content_type': response.headers.get('Content-Type', 'Noma\'lum'),
                'status_code': response.status_code,
                'content_length': len(response.content)
            }

            # Sayt mavjudligini tekshirish
            if response.status_code != 200:
                self.add_vulnerability(
                    'Saytga Kirish Muammosi',
                    'high',
                    f'Sayt {response.status_code} status kodi bilan javob berdi',
                    'Sayt mavjudligini tekshiring va server sozlamalarini qayta ko\'rib chiqing',
                    20,
                    'site_access'
                )

            self.html_content = response.text
            self.soup = BeautifulSoup(response.content, 'html.parser')

        except Exception as e:
            self.add_vulnerability(
                'Saytni Tekshirish Xatosi',
                'critical',
                f'Saytni tekshirishda xatolik: {str(e)}',
                'Sayt mavjudligini va tarmoq sozlamalarini tekshiring',
                40,
                'scan_error'
            )

    def scan_ssl_certificate(self, domain):
        """SSL sertifikatini tekshirish"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)

                    if cert_bin:
                        cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                        # Sertifikat ma'lumotlari
                        issuer = cert.issuer.rfc4514_string()
                        subject = cert.subject.rfc4514_string()
                        expires = cert.not_valid_after
                        days_until_expiry = (expires - datetime.now()).days

                        self.results['ssl_info'] = {
                            'issuer': issuer,
                            'subject': subject,
                            'expires': expires.strftime("%Y-%m-%d"),
                            'days_until_expiry': days_until_expiry,
                            'protocol': ssock.version()
                        }

                        # Sertifikat muddati tekshiruvi
                        if days_until_expiry < 30:
                            self.add_vulnerability(
                                'SSL Sertifikati Muddati Tugamoqda',
                                'high',
                                f'SSL sertifikati {days_until_expiry} kundan keyin muddati tugaydi',
                                'SSL sertifikatini shoshilinch yangilang',
                                35,
                                'ssl_expiring'
                            )

        except socket.timeout:
            self.add_vulnerability(
                'SSL Ulanish Vaqti Tugadi',
                'medium',
                'SSL sertifikatini tekshirish uchun ulanish vaqti tugadi',
                'Server ulanishini tekshiring',
                20,
                'ssl_timeout'
            )
        except Exception as e:
            self.add_vulnerability(
                'SSL Sertifikati Muammosi',
                'medium',
                f'SSL sertifikati tekshiruvi xatosi: {str(e)}',
                'SSL sertifikatini tekshiring va sozlang',
                25,
                'ssl_error'
            )

    def scan_dns_records(self, domain):
        """DNS yozuvlarini tekshirish"""
        try:
            # A yozuvlari
            a_records = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(ip) for ip in a_records]

            # MX yozuvlari
            mx_servers = []
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_servers = [str(mx.exchange) for mx in mx_records]
            except Exception as e:
                print(f"MX record xatosi: {e}")

            self.results['dns_info'] = {
                'ip_addresses': ip_addresses,
                'mx_servers': mx_servers,
                'domain': domain
            }

        except dns.resolver.NoAnswer:
            print(f"DNS javob yo'q: {domain}")
            self.results['dns_info'] = {'error': 'DNS javob yo\'q'}
        except dns.resolver.NXDOMAIN:
            print(f"Domain topilmadi: {domain}")
            self.results['dns_info'] = {'error': 'Domain topilmadi'}
        except Exception as e:
            print(f"DNS tekshiruvi xatosi: {e}")
            self.results['dns_info'] = {'error': str(e)}

    def find_subdomains(self, domain):
        """Subdomenlarni topish"""
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'api', 'test',
                             'dev', 'staging', 'secure', 'portal', 'cpanel']
        found_subdomains = []

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                # Socket orqali tekshirish
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except socket.gaierror:
                continue
            except Exception as e:
                print(f"Subdomain tekshirish xatosi {full_domain}: {e}")
                continue

        self.results['subdomains'] = found_subdomains

        if found_subdomains:
            self.results['scan_details']['subdomains_found'] = len(found_subdomains)

    def analyze_security_headers(self):
        """Xavfsizlik headerlarini tahlil qilish"""
        security_headers = {
            'X-Frame-Options': None,
            'X-Content-Type-Options': None,
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'X-XSS-Protection': None,
            'Referrer-Policy': None
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
                    'Content-Security-Policy headerni qo\'shing va sozlang',
                    30,
                    'missing_csp'
                )

            if not security_headers['Strict-Transport-Security']:
                self.add_vulnerability(
                    'HSTS Headeri Yo\'q',
                    'medium',
                    'HTTP dan HTTPS ga avtomatik yo\'naltirish yo\'q',
                    'Strict-Transport-Security headerni qo\'shing',
                    20,
                    'missing_hsts'
                )

        except Exception as e:
            print(f"Header tahlili xatosi: {e}")

    def scan_vulnerabilities(self):
        """Zaifliklarni skanerlash"""
        if not hasattr(self, 'soup') or self.soup is None:
            return

        # 1. SQL Injection zaifliklari
        self.check_sql_injection()

        # 2. XSS zaifliklari
        self.check_xss_vulnerabilities()

        # 3. CSRF zaifliklari
        self.check_csrf_vulnerabilities()

        # 4. Sensitive fayllar
        self.check_sensitive_files()

        # 5. Ma'lumotlar sizib chiqishi
        self.check_information_disclosure()

    def check_sql_injection(self):
        """SQL Injection zaifliklarini tekshirish"""
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                method = form.get('method', 'get').lower()

                # Form parametrlarini tekshirish
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', '').lower()

                    # SQL injection belgilari
                    sql_keywords = ['select', 'insert', 'update', 'delete', 'union', 'drop', 'create']
                    if any(keyword in input_name.lower() for keyword in sql_keywords):
                        self.add_vulnerability(
                            'Potentsial SQL Injection Zaifligi',
                            'high',
                            f'Formda SQL injection belgilari topildi: {input_name}',
                            'Parametrli so\'rovlardan foydalaning va inputlarni tozalang',
                            40,
                            'sql_injection'
                        )
        except Exception as e:
            print(f"SQL injection tekshirish xatosi: {e}")

    def check_xss_vulnerabilities(self):
        """XSS zaifliklarini tekshirish"""
        try:
            scripts = self.soup.find_all('script')
            for script in scripts:
                script_content = script.string
                if script_content and 'alert' in script_content.lower() and 'test' in script_content.lower():
                    self.add_vulnerability(
                        'Potentsial XSS Zaifligi',
                        'medium',
                        'Saytda test XSS skriptlari topildi',
                        'Input validation va output encoding ni amalga oshiring',
                        35,
                        'xss_vulnerability'
                    )

            # Input maydonlarini tekshirish
            inputs = self.soup.find_all('input')
            for input_field in inputs:
                if not input_field.get('type') in ['hidden', 'submit', 'button']:
                    if not any(attr in str(input_field.attrs) for attr in ['pattern', 'maxlength', 'required']):
                        self.add_vulnerability(
                            'Validation Cheklovlari Yo\'q',
                            'low',
                            'Input maydonlarida validation cheklovlari yetarli emas',
                            'Input validation qo\'shing va ma\'lumotlarni tozalang',
                            15,
                            'missing_validation'
                        )
        except Exception as e:
            print(f"XSS tekshirish xatosi: {e}")

    def check_csrf_vulnerabilities(self):
        """CSRF zaifliklarini tekshirish"""
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                csrf_token = form.find('input', {'name': ['csrf', 'csrf_token', '_token']})
                if not csrf_token:
                    self.add_vulnerability(
                        'CSRF Himoyasi Yo\'q',
                        'medium',
                        'Formda CSRF tokeni topilmadi',
                        'CSRF tokenlarni qo\'shing va tekshiring',
                        25,
                        'missing_csrf'
                    )
        except Exception as e:
            print(f"CSRF tekshirish xatosi: {e}")

    def check_sensitive_files(self):
        """Himoyalangan fayllarni tekshirish"""
        sensitive_files = [
            'robots.txt', '.env', 'config.php', 'backup.zip',
            'admin.php', 'phpinfo.php', 'test.php', 'debug.php'
        ]

        base_url = self.target_url.rstrip('/')
        for file in sensitive_files:
            try:
                test_url = f"{base_url}/{file}"
                response = self.safe_request(test_url, timeout=5)

                if response and response.status_code == 200:
                    self.add_vulnerability(
                        f'Himoyalangan Fayl Ochiq: {file}',
                        'medium' if file == 'robots.txt' else 'high',
                        f'Himoyalangan fayl ochiq holatda topildi: {file}',
                        f'{file} faylini himoyalang yoki serverdan o\'chiring',
                        35 if file == 'robots.txt' else 45,
                        f'sensitive_file_{file}'
                    )
            except Exception as e:
                print(f"Sensitive file tekshirish xatosi {file}: {e}")
                continue

    def check_information_disclosure(self):
        """Ma'lumotlar sizib chiqishini tekshirish"""
        # Server versiyasi
        server = self.results['server_info'].get('server', '')
        if server and server != 'Noma\'lum':
            self.add_vulnerability(
                'Server Versiyasi Oshkor Qilingan',
                'low',
                f'Server versiyasi oshkor qilingan: {server}',
                'Server headerini yashiring yoki o\'chiring',
                10,
                'server_info_disclosure'
            )

        # X-Powered-By headeri
        try:
            response = self.safe_request(self.target_url, timeout=5)
            if response:
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    self.add_vulnerability(
                        'Texnologiya Ma\'lumoti Oshkor Qilingan',
                        'low',
                        f'Texnologiya ma\'lumoti oshkor qilingan: {powered_by}',
                        'X-Powered-By headerini o\'chiring',
                        5,
                        'tech_info_disclosure'
                    )
        except Exception as e:
            print(f"Information disclosure tekshirish xatosi: {e}")

    def detect_technology_stack(self):
        """Texnologiya stackini aniqlash"""
        try:
            tech_stack = []
            if not hasattr(self, 'html_content'):
                return

            html_lower = self.html_content.lower()

            # CMS aniqlash
            if 'wp-content' in html_lower or 'wordpress' in html_lower:
                tech_stack.append('WordPress')
            if 'joomla' in html_lower:
                tech_stack.append('Joomla')
            if 'drupal' in html_lower:
                tech_stack.append('Drupal')

            # Frameworklar
            if 'react' in html_lower:
                tech_stack.append('React')
            if 'vue' in html_lower:
                tech_stack.append('Vue.js')
            if 'angular' in html_lower:
                tech_stack.append('Angular')
            if 'jquery' in html_lower:
                tech_stack.append('jQuery')

            # Server texnologiyalari
            server = self.results['server_info'].get('server', '')
            if 'nginx' in server.lower():
                tech_stack.append('nginx')
            elif 'apache' in server.lower():
                tech_stack.append('Apache')

            self.results['tech_stack'] = tech_stack
        except Exception as e:
            print(f"Technology stack aniqlash xatosi: {e}")

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
            self.results['risk_score'] = 0
            self.results['security_score'] = 100

    def generate_recommendations(self):
        """Tavsiyalar generatsiya qilish"""
        try:
            recommendations = []
            vulns = self.results['vulnerabilities']

            # Severity asosida tavsiyalar
            if any(v['severity'] == 'critical' for v in vulns):
                recommendations.append("Darvozabon darajadagi zaifliklarni darhol bartaraf eting")

            if any(v['severity'] == 'high' for v in vulns):
                recommendations.append("Yuqori darajadagi xavflarni birinchi navbatda hal qiling")

            # Maxsus tavsiyalar
            if any('ssl' in v['key'] for v in vulns):
                recommendations.append("SSL sertifikatini yangilang va HTTPS ni majburiy qiling")

            if any('xss' in v['key'] for v in vulns):
                recommendations.append("Input validation va output encoding ni mustahkamlang")

            if any('sql' in v['key'] for v in vulns):
                recommendations.append("Ma'lumotlar bazasi so'rovlarini parametrlashtiring")

            if not recommendations:
                recommendations.append("Sayt xavfsizlik jihatdan yaxshi holatda. Muntazam monitoringni davom ettiring")

            self.results['recommendations'] = recommendations
        except Exception as e:
            print(f"Recommendation generation xatosi: {e}")
            self.results['recommendations'] = ["Tavsiyalar generatsiya qilishda xatolik"]


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

        print(f"🎬 Haqiqiy skanerlash boshlandi: {target_url}")

        scanner = AdvancedSecurityScanner(target_url)
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


@app.route('/results/<scan_id>')
def get_scan_results(scan_id):
    """Test uchun natijalar"""
    try:
        # Real skanerlash qilish uchun test ma'lumotlari
        test_results = {
            'success': True,
            'status': 'done',
            'results': {
                'vulnerabilities': [
                    {
                        'type': 'SSL Sertifikati Muddati Tugamoqda',
                        'severity': 'high',
                        'description': 'SSL sertifikati 15 kundan keyin muddati tugaydi',
                        'solution': 'SSL sertifikatini shoshilinch yangilang',
                        'risk_score': 35,
                        'id': 'VULN-001',
                        'key': 'ssl_expiring',
                        'icon': '🔥'
                    },
                    {
                        'type': 'Content-Security-Policy Yo\'q',
                        'severity': 'high',
                        'description': 'CSP headeri yo\'q, XSS hujumlariga qarshi himoya zaif',
                        'solution': 'Content-Security-Policy headerni qo\'shing va sozlang',
                        'risk_score': 30,
                        'id': 'VULN-002',
                        'key': 'missing_csp',
                        'icon': '⚠️'
                    },
                    {
                        'type': 'X-Frame-Options Headeri Yo\'q',
                        'severity': 'medium',
                        'description': 'Clickjacking hujumlariga qarshi himoya yo\'q',
                        'solution': 'X-Frame-Options: SAMEORIGIN headerni qo\'shing',
                        'risk_score': 25,
                        'id': 'VULN-003',
                        'key': 'missing_xframe',
                        'icon': '🔶'
                    }
                ],
                'security_score': 70,
                'risk_score': 30,
                'response_time': 1.2,
                'server_info': {
                    'server': 'nginx/1.18.0',
                    'status_code': 200,
                    'content_type': 'text/html'
                },
                'security_headers': {
                    'X-Frame-Options': None,
                    'Content-Security-Policy': None,
                    'Strict-Transport-Security': 'max-age=31536000'
                },
                'tech_stack': ['nginx', 'PHP', 'WordPress'],
                'recommendations': [
                    "SSL sertifikatini yangilang",
                    "Content-Security-Policy headerni qo'shing",
                    "X-Frame-Options headerni qo'shing"
                ]
            },
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target_url': 'https://example.com',
            'scan_id': scan_id
        }

        return jsonify(test_results)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def create_detailed_report(results, scan_date, target_url, language='uz'):
    """To'liq batafsil HTML hisobot yaratish"""

    try:
        print(f"📊 HTML hisobot yaratilmoqda: {target_url}")

        # Zaiflik statistikasi
        vulnerabilities = results.get('vulnerabilities', [])
        vuln_stats = {
            'critical': len([v for v in vulnerabilities if v['severity'] == 'critical']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'high']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'medium']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'low']),
            'info': len([v for v in vulnerabilities if v['severity'] == 'info'])
        }

        total_vulns = sum(vuln_stats.values())
        security_score = results.get('security_score', 0)
        risk_score = results.get('risk_score', 0)

        # Zaifliklar HTML
        vulnerabilities_html = ""
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_color = {
                    'critical': '#ff003c',
                    'high': '#ff6b00',
                    'medium': '#ffc107',
                    'low': '#00ff41',
                    'info': '#007bff'
                }.get(vuln['severity'], '#666')

                vulnerabilities_html += f"""
                <div style="border-left: 5px solid {severity_color}; background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <h3 style="color: {severity_color}; margin: 0;">{vuln.get('icon', '🔍')} {vuln['type']}</h3>
                        <span style="background: {severity_color}; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold;">
                            {vuln['severity'].upper()}
                        </span>
                    </div>

                    <div style="margin: 10px 0;">
                        <h4 style="color: #333; margin-bottom: 5px;">📝 Tavsif</h4>
                        <p style="margin: 0; color: #555;">{vuln['description']}</p>
                    </div>

                    <div style="margin: 10px 0;">
                        <h4 style="color: #333; margin-bottom: 5px;">🛠️ Yechim</h4>
                        <p style="margin: 0; color: #555;">{vuln['solution']}</p>
                    </div>

                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 15px;">
                        <span style="color: #666; font-size: 14px;">ID: {vuln['id']}</span>
                        <span style="background: #ff6b00; color: white; padding: 3px 10px; border-radius: 15px; font-weight: bold;">
                            Xavf balli: {vuln['risk_score']}
                        </span>
                    </div>
                </div>
                """
        else:
            vulnerabilities_html = """
            <div style="text-align: center; padding: 40px; background: #e6ffe6; border-radius: 10px;">
                <h3 style="color: #00ff41;">✅ Ajoyib!</h3>
                <p>Hech qanday zaiflik aniqlanmadi. Sayt xavfsiz holatda.</p>
            </div>
            """

        # Infografika
        infographic_html = f"""
        <div style="text-align: center; margin: 30px 0; padding: 20px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 15px; color: white;">
            <h3 style="margin-bottom: 20px;">📊 Xavf Statistikasi</h3>

            <div style="display: flex; justify-content: center; gap: 30px; flex-wrap: wrap;">
                <div style="text-align: center;">
                    <div style="width: 80px; height: 80px; border-radius: 50%; background: #ff003c; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                        <span style="font-size: 24px; font-weight: bold;">{vuln_stats['critical']}</span>
                    </div>
                    <span style="font-weight: bold;">CRITICAL</span>
                </div>

                <div style="text-align: center;">
                    <div style="width: 70px; height: 70px; border-radius: 50%; background: #ff6b00; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                        <span style="font-size: 20px; font-weight: bold;">{vuln_stats['high']}</span>
                    </div>
                    <span style="font-weight: bold;">HIGH</span>
                </div>

                <div style="text-align: center;">
                    <div style="width: 60px; height: 60px; border-radius: 50%; background: #ffc107; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                        <span style="font-size: 18px; font-weight: bold;">{vuln_stats['medium']}</span>
                    </div>
                    <span style="font-weight: bold;">MEDIUM</span>
                </div>

                <div style="text-align: center;">
                    <div style="width: 50px; height: 50px; border-radius: 50%; background: #00ff41; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                        <span style="font-size: 16px; font-weight: bold;">{vuln_stats['low']}</span>
                    </div>
                    <span style="font-weight: bold;">LOW</span>
                </div>
            </div>
        </div>
        """

        # Score Circles
        score_html = f"""
        <div style="display: flex; justify-content: center; gap: 50px; margin: 30px 0;">
            <div style="text-align: center;">
                <div style="width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#00ff41 0% {security_score}%, #ddd {security_score}% 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 10px;">
                    <div style="width: 100px; height: 100px; border-radius: 50%; background: white; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <span style="font-size: 24px; font-weight: bold; color: #00ff41;">{security_score}</span>
                        <span style="font-size: 12px; color: #666;">Xavfsizlik</span>
                    </div>
                </div>
                <h4 style="color: #00ff41; margin: 0;">XAVFSIZLIK</h4>
            </div>

            <div style="text-align: center;">
                <div style="width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#ff003c 0% {risk_score}%, #ddd {risk_score}% 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 10px;">
                    <div style="width: 100px; height: 100px; border-radius: 50%; background: white; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <span style="font-size: 24px; font-weight: bold; color: #ff003c;">{risk_score}</span>
                        <span style="font-size: 12px; color: #666;">Xavf</span>
                    </div>
                </div>
                <h4 style="color: #ff003c; margin: 0;">XAVF</h4>
            </div>
        </div>
        """

        # Server ma'lumotlari
        server_info = results.get('server_info', {})
        server_info_html = f"""
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #00ff41; margin-bottom: 15px;">🖥️ Server Ma'lumotlari</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div><strong>Server:</strong> {server_info.get('server', 'Noma lum')}</div>
                <div><strong>Status Code:</strong> {server_info.get('status_code', 'Noma lum')}</div>
                <div><strong>Content Type:</strong> {server_info.get('content_type', 'Noma lum')}</div>
                <div><strong>Response Time:</strong> {results.get('response_time', 0)}s</div>
            </div>
        </div>
        """

        # Security Headers
        security_headers = results.get('security_headers', {})
        headers_html_parts = []
        for header, value in security_headers.items():
            status = "✅ Mavjud" if value else "❌ Yo'q"
            color = "#00ff41" if value else "#ff003c"
            headers_html_parts.append(f"""
                <div style="padding: 8px; border-left: 3px solid {color};">
                    <strong>{header}:</strong> <span style="color: {color};">{status}</span>
                </div>
            """)

        headers_html = f"""
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #00ff41; margin-bottom: 15px;">🛡️ Xavfsizlik Headerlari</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                {''.join(headers_html_parts)}
            </div>
        </div>
        """

        # Texnologiya Stacki
        tech_stack = results.get('tech_stack', [])
        tech_html = ""
        if tech_stack:
            tech_items = ''.join(
                f'<span style="background: #667eea; color: white; padding: 5px 15px; border-radius: 20px;">{tech}</span>'
                for tech in tech_stack)
            tech_html = f"""
            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <h3 style="color: #00ff41; margin-bottom: 15px;">🔧 Texnologiya Stacki</h3>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    {tech_items}
                </div>
            </div>
            """

        # Tavsiyalar
        recommendations = results.get('recommendations', [])
        rec_html = ""
        if recommendations:
            rec_items = ''.join(f'<li style="margin: 8px 0; color: #555;">{rec}</li>' for rec in recommendations)
            rec_html = f"""
            <div style="background: #e6f7ff; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #007bff;">
                <h3 style="color: #007bff; margin-bottom: 15px;">💡 Tavsiyalar</h3>
                <ul style="margin: 0; padding-left: 20px;">
                    {rec_items}
                </ul>
            </div>
            """

        # Umumiy HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>CyberGuard Pro - Security Report</title>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    margin: 40px;
                    line-height: 1.6;
                    color: #333;
                    background: white;
                }}
                .report-container {{
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    border: 2px solid #00ff41;
                }}
                .header {{
                    text-align: center;
                    border-bottom: 3px solid #00ff41;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                    background: linear-gradient(45deg, #0a0a0a, #1a1a2e);
                    color: white;
                    padding: 30px;
                    border-radius: 15px;
                }}
                .cyber-title {{
                    font-size: 2.5em;
                    color: #00ff41;
                    margin-bottom: 10px;
                    font-weight: bold;
                }}
                .scan-info {{
                    background: #f8f9fa;
                    padding: 25px;
                    border-radius: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #00ff41;
                }}
                .summary-grid {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 20px;
                    margin: 30px 0;
                }}
                .summary-card {{
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    color: white;
                    padding: 25px;
                    border-radius: 15px;
                    text-align: center;
                    border: none;
                }}
                .summary-number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="report-container">
                <!-- Header -->
                <div class="header">
                    <h1 class="cyber-title">🚀 CYBERGUARD PRO</h1>
                    <h2>Professional Security Scan Report</h2>
                    <p>Hollywood-style Security Analysis</p>
                </div>

                <!-- Scan Information -->
                <div class="scan-info">
                    <h3>📊 Skanerlash Ma lumotlari</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div><strong>🔗 Sayt Manzili:</strong> {target_url}</div>
                        <div><strong>📅 Sana:</strong> {scan_date}</div>
                        <div><strong>🛡️ Xavfsizlik Darajasi:</strong> {security_score}/100</div>
                        <div><strong>⚠️ Xavf Darajasi:</strong> {risk_score}/100</div>
                        <div><strong>🔍 Aniqlangan Zaifliklar:</strong> {total_vulns}</div>
                        <div><strong>⚡ Javob Vaqti:</strong> {results.get('response_time', 0)}s</div>
                    </div>
                </div>

                {score_html}
                {infographic_html}

                <!-- Summary Grid -->
                <div class="summary-grid">
                    <div class="summary-card" style="background: linear-gradient(135deg, #ff003c, #ff6b00);">
                        <div class="summary-number">{vuln_stats['critical']}</div>
                        <div>CRITICAL</div>
                    </div>
                    <div class="summary-card" style="background: linear-gradient(135deg, #ff6b00, #ffc107);">
                        <div class="summary-number">{vuln_stats['high']}</div>
                        <div>HIGH</div>
                    </div>
                    <div class="summary-card" style="background: linear-gradient(135deg, #ffc107, #ffcc00);">
                        <div class="summary-number">{vuln_stats['medium']}</div>
                        <div>MEDIUM</div>
                    </div>
                    <div class="summary-card" style="background: linear-gradient(135deg, #00ff41, #00cc33);">
                        <div class="summary-number">{vuln_stats['low']}</div>
                        <div>LOW</div>
                    </div>
                </div>

                {server_info_html}
                {headers_html}
                {tech_html}

                <!-- Vulnerabilities -->
                <h2 style="color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; margin-top: 40px;">
                    🔍 Aniqlangan Zaifliklar ({total_vulns})
                </h2>
                {vulnerabilities_html}

                {rec_html}

                <!-- Footer -->
                <div style="margin-top: 50px; text-align: center; color: #666; border-top: 1px solid #ddd; padding-top: 20px;">
                    <p><strong>Generated by CyberGuard Pro - Hollywood-style Security Scanner</strong></p>
                    <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p style="color: #00ff41;">© 2024 CyberGuard Pro. All systems operational.</p>
                </div>
            </div>
        </body>
        </html>
        """

        print("✅ HTML hisobot muvaffaqiyatli yaratildi")
        return html_content

    except Exception as e:
        print(f"❌ HTML hisobot yaratish xatosi: {e}")
        return """
        <html>
        <body>
            <h1>Xatolik yuz berdi</h1>
            <p>Hisobot yaratishda xatolik yuz berdi</p>
        </body>
        </html>
        """


@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'})

        results = data.get('results', {})
        scan_date = data.get('scan_date', '')
        target_url = data.get('target_url', '')

        print(f"📄 HTML hisobot yaratilmoqda: {target_url}")
        print(f"📊 Natijalar: {len(results.get('vulnerabilities', []))} ta zaiflik")

        # To'liq HTML hisobot yaratish
        html_content = create_detailed_report(results, scan_date, target_url)

        # HTML fayl sifatida qaytarish
        html_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix='.html',
            mode='w',
            encoding='utf-8'
        )
        html_file.write(html_content)
        html_file.flush()  # Ma'lumotlarni diskga yozish
        html_file.close()

        print(f"✅ HTML hisobot fayliga yozildi: {html_file.name}")

        return send_file(
            html_file.name,
            as_attachment=True,
            download_name=f'cyberguard_report_{int(time.time())}.html',
            mimetype='text/html'
        )

    except Exception as e:
        print(f"❌ HTML yaratish xatosi: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    # Papkalarni yaratish
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)

    # Session sozlamalari
    requests.packages.urllib3.disable_warnings()

    print("🚀 Advanced CyberGuard Pro starting...")
    print("🔍 Endi saytlar haqiqiy tahlil qilinadi!")

    try:
        app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
    except Exception as e:
        print(f"Server ishga tushirish xatosi: {e}")
