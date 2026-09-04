"""
fix_all.py – Consolidated patch script
Merged from: fix.py, fix_main.py, fix_admin.py

Patches:
  1. main.py   – Injects Xendit subscribe, checkout, and webhook routes
  2. admin.html – Adds subscription nav links (desktop + mobile),
                  subscription modal, and JS open/close helpers

Run once from the SaaSWebApp directory:
    python fix_all.py
"""

import sys
import re

# ─────────────────────────────────────────────
# 1. Patch main.py – add Xendit subscription routes
# ─────────────────────────────────────────────

print("[1/2] Patching main.py ...")

with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_block = '''# Main routes

@app.route('/subscribe', methods=['GET'])
def subscribe_page():
    return render_template('subscribe.html')

@app.route('/api/xendit/checkout', methods=['POST'])
def xendit_checkout():
    plan = request.form.get('plan')
    company_id = session.get('company_id')
    if not company_id:
        return 'Not logged in or no company selected', 401
    
    amount = 20 if plan == 'monthly' else 200
    
    secret_key = (os.environ.get('XENDIT_SECRET_KEY') or '').strip()
    base_url = (os.environ.get('XENDIT_API_BASE_URL') or 'https://api.xendit.co').strip().rstrip('/')
    
    if not secret_key:
        return 'Xendit not configured', 500
        
    import datetime
    payload = {
        'external_id': f'sub-{company_id}-{plan}-{int(datetime.datetime.now().timestamp())}',
        'amount': amount,
        'description': f'Subscription: {plan} plan',
        'invoice_duration': 86400,
        'currency': 'PHP',
        'success_redirect_url': url_for('dashboard', _external=True)
    }
    
    try:
        import requests
        response = requests.post(
            f"{base_url}/v2/invoices",
            json=payload,
            auth=(secret_key, ""),
            headers={"Content-Type": "application/json"}
        )
        data = response.json()
        if response.ok and 'invoice_url' in data:
            return redirect(data['invoice_url'])
        else:
            return f"Failed to create invoice: {data}", 500
    except Exception as e:
        return f"Error: {e}", 500

@app.route('/api/xendit/webhook', methods=['POST'])
def xendit_webhook():
    callback_token = request.headers.get('x-callback-token')
    data = request.json
    
    if not data:
        return 'No payload', 400
        
    status = data.get('status')
    external_id = data.get('external_id', '')
    
    if status == 'PAID' and external_id.startswith('sub-'):
        parts = external_id.split('-')
        if len(parts) >= 3:
            company_id = parts[1]
            plan = parts[2]
            
            import pymysql
            from config import Config
            conn = pymysql.connect(
                host=Config.MYSQL_HOST,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASSWORD,
                db=Config.MYSQL_DB
            )
            cur = conn.cursor()
            
            monthly_price = 20.00 if plan == 'monthly' else 200.00
            seats_limit = 100 
            requests_limit = 1000
            interval_str = "1 MONTH" if plan == 'monthly' else "1 YEAR"
            
            cur.execute(
                f"""
                INSERT INTO tenant_subscriptions 
                (company_id, plan_name, subscription_status, monthly_price, seats_limit, requests_limit, ends_at)
                VALUES (%s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL {interval_str}))
                ON DUPLICATE KEY UPDATE
                plan_name=VALUES(plan_name),
                subscription_status=VALUES(subscription_status),
                monthly_price=VALUES(monthly_price),
                seats_limit=VALUES(seats_limit),
                requests_limit=VALUES(requests_limit),
                ends_at=DATE_ADD(NOW(), INTERVAL {interval_str})
                """,
                (company_id, plan.upper(), 'ACTIVE', monthly_price, seats_limit, requests_limit)
            )
            conn.commit()
            cur.close()
            conn.close()
            
    return jsonify({'status': 'ok'}), 200

@app.route("/")'''

new_content = re.sub(
    r'# Main routes.*?@app\.route\("/"\)',
    new_block,
    content,
    flags=re.DOTALL
)

with open('main.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("  -> main.py patched successfully.")

# ─────────────────────────────────────────────
# 2. Patch templates/admin.html – subscription UI
# ─────────────────────────────────────────────

print("[2/2] Patching templates/admin.html ...")

with open('templates/admin.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 2a. Remove ALL existing /subscribe links
content = re.sub(
    r'<a[^>]*href="/subscribe"[^>]*>.*?</a>',
    '',
    content,
    flags=re.DOTALL
)

# 2b. Add desktop Subscription nav link after Settings
desktop_link = '''        <a id="nav-settings" class="nav-item" onclick="switchView('settings')">
          <div class="nav-item-content">
            <i class="fa-solid fa-gear"></i>
            <span>Settings</span>
          </div>
        </a>
        <a onclick="openSubscriptionModal()" class="nav-item" style="color: #1FA15A; font-weight: bold; cursor: pointer;">
          <div class="nav-item-content">
            <i class="fa-solid fa-credit-card"></i>
            <span>Subscription</span>
          </div>
        </a>'''

content = re.sub(
    r'<a id="nav-settings" class="nav-item" onclick="switchView\(\'settings\'\)"\>\s*<div class="nav-item-content"\>\s*<i class="fa-solid fa-gear"\></i\>\s*<span\>Settings\</span\>\s*</div\>\s*</a\>',
    desktop_link,
    content
)

# 2c. Add mobile Subscription nav link after mobile Settings
mobile_link = '''<a onclick="switchView('settings'); closeMobileMenu();">Settings</a>
          <a onclick="openSubscriptionModal(); closeMobileMenu();" style="color: #1FA15A; font-weight: bold; cursor: pointer;">Subscription</a>'''

content = re.sub(
    r'<a onclick="switchView\(\'settings\'\);\s*closeMobileMenu\(\);\s*"\>Settings\</a\>',
    mobile_link,
    content
)

# 2d. Insert Subscription modal before <!-- CC MODAL -->
modal_html = '''
    <!-- SUBSCRIPTION MODAL -->
    <div id="subscriptionModal" class="modal-overlay" style="display:none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 9999; justify-content: center; align-items: center;">
      <div class="modal-content" style="background: white; border-radius: 12px; padding: 30px; width: 100%; max-width: 700px; text-align: center; position: relative;">
        <button type="button" onclick="closeSubscriptionModal()" style="position: absolute; top: 15px; right: 15px; background: transparent; border: none; font-size: 1.5rem; cursor: pointer;">&times;</button>
        <h2 style="margin-bottom: 20px;">Choose Your Subscription Plan</h2>
        <p style="margin-bottom: 30px;">Upgrade to unlock higher limits and premium features for your organization.</p>
        
        <div style="display: flex; gap: 20px; justify-content: center; flex-wrap: wrap;">
            <div style="border: 2px solid #eeeff2; border-radius: 12px; padding: 20px; width: 250px; transition: 0.3s;" onmouseover="this.style.borderColor='#1FA15A'" onmouseout="this.style.borderColor='#eeeff2'">
                <h3>Monthly Plan</h3>
                <div style="font-size: 2rem; font-weight: bold; color: #1FA15A; margin: 15px 0;">$20<span style="font-size: 1rem; color: #777;">/mo</span></div>
                <ul style="list-style: none; padding: 0; margin-bottom: 20px; text-align: left;">
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">&#10003; Increased limits</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">&#10003; Premium support</li>
                    <li style="padding: 5px 0;">&#10003; Detailed analytics</li>
                </ul>
                <form action="/api/xendit/checkout" method="POST">
                    <input type="hidden" name="plan" value="monthly">
                    <button type="submit" style="width: 100%; padding: 10px; background: #1FA15A; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">Subscribe Monthly</button>
                </form>
            </div>
            
            <div style="border: 2px solid #eeeff2; border-radius: 12px; padding: 20px; width: 250px; transition: 0.3s;" onmouseover="this.style.borderColor='#0ea5a4'" onmouseout="this.style.borderColor='#eeeff2'">
                <h3>Annual Plan</h3>
                <div style="font-size: 2rem; font-weight: bold; color: #0ea5a4; margin: 15px 0;">$200<span style="font-size: 1rem; color: #777;">/yr</span></div>
                <ul style="list-style: none; padding: 0; margin-bottom: 20px; text-align: left;">
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">&#10003; Save $40 per year</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">&#10003; Increased limits</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">&#10003; Premium support</li>
                    <li style="padding: 5px 0;">&#10003; Detailed analytics</li>
                </ul>
                <form action="/api/xendit/checkout" method="POST">
                    <input type="hidden" name="plan" value="annual">
                    <button type="submit" style="width: 100%; padding: 10px; background: #0ea5a4; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">Subscribe Annually</button>
                </form>
            </div>
        </div>
      </div>
    </div>
    
    <!-- CC MODAL -->
'''
content = content.replace('<!-- CC MODAL -->', modal_html)

# 2e. Add JS open/close functions before </script></body>
js_html = '''
function openSubscriptionModal() {
    const el = document.getElementById('subscriptionModal');
    if (el) el.style.display = 'flex';
}
function closeSubscriptionModal() {
    const el = document.getElementById('subscriptionModal');
    if (el) el.style.display = 'none';
}
</script>
</body>'''
content = content.replace('</script>\n  </body>', js_html)
content = content.replace('</script>\n</body>', js_html)

with open('templates/admin.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("  -> templates/admin.html patched successfully.")
print("\nAll patches applied. You can now delete this script.")
