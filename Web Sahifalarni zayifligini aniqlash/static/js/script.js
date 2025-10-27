// script.js fayliga quyidagi funksiyani qo'shing

document.getElementById('downloadPdfButton').addEventListener('click', function() {
    if (!window.lastScanResults) {
        showNotification('⚠️ Avval saytni skanerlang!', 'warning');
        return;
    }

    const button = this;
    const originalText = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PDF Yaratilmoqda...';

    fetch('/download-pdf', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(window.lastScanResults)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('PDF yaratishda xatolik');
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;

        // Fayl nomini yaxshilaymiz
        const targetUrl = window.lastScanResults.target_url || 'report';
        const cleanUrl = targetUrl.replace('https://', '').replace('http://', '').replace(/\//g, '_');
        a.download = `cyberguard_report_${cleanUrl}_${Date.now()}.html`;

        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        showNotification('✅ PDF hisobot muvaffaqiyatli yuklab olindi!', 'success');
    })
    .catch(error => {
        console.error('PDF yuklash xatosi:', error);
        showNotification('❌ PDF yuklashda xatolik: ' + error.message, 'error');
    })
    .finally(() => {
        button.disabled = false;
        button.innerHTML = originalText;
    });
});
# app.py faylining oxiriga quyidagi funksiyani qo'shing

def create_detailed_report(results, scan_date, target_url, language='uz'):
    """To'liq batafsil PDF hisobot yaratish"""

    # Zaiflik statistikasi
    vuln_stats = {
        'critical': len([v for v in results.get('vulnerabilities', []) if v['severity'] == 'critical']),
        'high': len([v for v in results.get('vulnerabilities', []) if v['severity'] == 'high']),
        'medium': len([v for v in results.get('vulnerabilities', []) if v['severity'] == 'medium']),
        'low': len([v for v in results.get('vulnerabilities', []) if v['severity'] == 'low']),
        'info': len([v for v in results.get('vulnerabilities', []) if v['severity'] == 'info'])
    }

    total_vulns = sum(vuln_stats.values())

    # Zaifliklar HTML
    vulnerabilities_html = ""
    for vuln in results.get('vulnerabilities', []):
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

    # Infografika SVG
    infographic_svg = f"""
    <div style="text-align: center; margin: 30px 0; padding: 20px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 15px;">
        <h3 style="color: white; margin-bottom: 20px;">📊 Xavf Statistikasi</h3>

        <div style="display: flex; justify-content: center; gap: 30px; flex-wrap: wrap;">
            <!-- Critical -->
            <div style="text-align: center;">
                <div style="width: 80px; height: 80px; border-radius: 50%; background: #ff003c; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                    <span style="color: white; font-size: 24px; font-weight: bold;">{vuln_stats['critical']}</span>
                </div>
                <span style="color: white; font-weight: bold;">CRITICAL</span>
            </div>

            <!-- High -->
            <div style="text-align: center;">
                <div style="width: 70px; height: 70px; border-radius: 50%; background: #ff6b00; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                    <span style="color: white; font-size: 20px; font-weight: bold;">{vuln_stats['high']}</span>
                </div>
                <span style="color: white; font-weight: bold;">HIGH</span>
            </div>

            <!-- Medium -->
            <div style="text-align: center;">
                <div style="width: 60px; height: 60px; border-radius: 50%; background: #ffc107; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                    <span style="color: white; font-size: 18px; font-weight: bold;">{vuln_stats['medium']}</span>
                </div>
                <span style="color: white; font-weight: bold;">MEDIUM</span>
            </div>

            <!-- Low -->
            <div style="text-align: center;">
                <div style="width: 50px; height: 50px; border-radius: 50%; background: #00ff41; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; border: 3px solid white;">
                    <span style="color: white; font-size: 16px; font-weight: bold;">{vuln_stats['low']}</span>
                </div>
                <span style="color: white; font-weight: bold;">LOW</span>
            </div>
        </div>
    </div>
    """

    # Security Score Circles
    security_score = results.get('security_score', 0)
    risk_score = results.get('risk_score', 0)

    score_html = f"""
    <div style="display: flex; justify-content: center; gap: 50px; margin: 30px 0;">
        <!-- Security Score -->
        <div style="text-align: center;">
            <div style="width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#00ff41 0% {security_score}%, #ddd {security_score}% 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; position: relative;">
                <div style="width: 100px; height: 100px; border-radius: 50%; background: white; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                    <span style="font-size: 24px; font-weight: bold; color: #00ff41;">{security_score}</span>
                    <span style="font-size: 12px; color: #666;">Xavfsizlik</span>
                </div>
            </div>
            <h4 style="color: #00ff41; margin: 0;">XAVFSIZLIK</h4>
        </div>

        <!-- Risk Score -->
        <div style="text-align: center;">
            <div style="width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#ff003c 0% {risk_score}%, #ddd {risk_score}% 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; position: relative;">
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
    server_html = f"""
    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h3 style="color: #00ff41; margin-bottom: 15px;">🖥️ Server Ma'lumotlari</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div><strong>Server:</strong> {server_info.get('server', 'Noma\'lum')}</div>
            <div><strong>Status Code:</strong> {server_info.get('status_code', 'Noma\'lum')}</div>
            <div><strong>Content Type:</strong> {server_info.get('content_type', 'Noma\'lum')}</div>
            <div><strong>Response Time:</strong> {results.get('response_time', 0)}s</div>
        </div>
    </div>
    """

    # Security Headers
    security_headers = results.get('security_headers', {})
    headers_html = """
    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h3 style="color: #00ff41; margin-bottom: 15px;">🛡️ Xavfsizlik Headerlari</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
    """

    for header, value in security_headers.items():
        status = "✅ Mavjud" if value else "❌ Yo'q"
        color = "#00ff41" if value else "#ff003c"
        headers_html += f"""
            <div style="padding: 8px; border-left: 3px solid {color};">
                <strong>{header}:</strong> <span style="color: {color};">{status}</span>
            </div>
        """

    headers_html += "</div></div>"

    # Texnologiya Stacki
    tech_stack = results.get('tech_stack', [])
    tech_html = ""
    if tech_stack:
        tech_html = f"""
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #00ff41; margin-bottom: 15px;">🔧 Texnologiya Stacki</h3>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                {"".join(f'<span style="background: #667eea; color: white; padding: 5px 15px; border-radius: 20px;">{tech}</span>' for tech in tech_stack)}
            </div>
        </div>
        """

    # Tavsiyalar
    recommendations = results.get('recommendations', [])
    rec_html = ""
    if recommendations:
        rec_html = f"""
        <div style="background: #e6f7ff; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #007bff;">
            <h3 style="color: #007bff; margin-bottom: 15px;">💡 Tavsiyalar</h3>
            <ul style="margin: 0; padding-left: 20px;">
                {"".join(f'<li style="margin: 8px 0; color: #555;">{rec}</li>' for rec in recommendations)}
            </ul>
        </div>
        """

    # Umumiy HTML
    return f"""
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
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }}
            .report-container {{
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
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
                text-shadow: 0 0 10px #00ff41;
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
            @media print {{
                body {{
                    background: white !important;
                }}
                .report-container {{
                    box-shadow: none !important;
                    padding: 20px !important;
                }}
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
                <h3>📊 Skanerlash Ma'lumotlari</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div><strong>🔗 Sayt Manzili:</strong> {target_url}</div>
                    <div><strong>📅 Sana:</strong> {scan_date}</div>
                    <div><strong>🛡️ Xavfsizlik Darajasi:</strong> {security_score}/100</div>
                    <div><strong>⚠️ Xavf Darajasi:</strong> {risk_score}/100</div>
                    <div><strong>🔍 Aniqlangan Zaifliklar:</strong> {total_vulns}</div>
                    <div><strong>⚡ Javob Vaqti:</strong> {results.get('response_time', 0)} soniya</div>
                </div>
            </div>

            {score_html}
            {infographic_svg}

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

            {server_html}
            {headers_html}
            {tech_html}

            <!-- Vulnerabilities -->
            <h2 style="color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; margin-top: 40px;">
                🔍 Aniqlangan Zaifliklar ({total_vulns})
            </h2>
            {vulnerabilities_html if vulnerabilities_html else '''
            <div style="text-align: center; padding: 40px; background: #e6ffe6; border-radius: 10px;">
                <h3 style="color: #00ff41;">✅ Ajoyib!</h3>
                <p>Hech qanday zaiflik aniqlanmadi. Sayt xavfsiz holatda.</p>
            </div>
            '''}

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

# PDF download route ni yangilaymiz
@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'})

        results = data.get('results', {})
        scan_date = data.get('scan_date', '')
        target_url = data.get('target_url', '')

        print(f"📄 PDF hisobot yaratilmoqda: {target_url}")

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
        html_file.close()

        print(f"✅ PDF hisobot yaratildi: {html_file.name}")

        return send_file(
            html_file.name,
            as_attachment=True,
            download_name=f'cyberguard_report_{target_url.replace("https://", "").replace("http://", "").replace("/", "_")}_{int(time.time())}.html',
            mimetype='text/html'
        )

    except Exception as e:
        print(f"❌ PDF yaratish xatosi: {e}")
        return jsonify({'success': False, 'error': str(e)})
