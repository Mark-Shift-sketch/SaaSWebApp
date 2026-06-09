import sys, re

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

new_content = re.sub(r'# Main routes.*?@app\.route\("/"\)', new_block, content, flags=re.DOTALL)
with open('main.py', 'w', encoding='utf-8') as f:
    f.write(new_content)
print('Fixed it!')
