import sys, re

with open('templates/admin.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove ALL occurrences of the /subscribe link
content = re.sub(
    r'<a[^>]*href="/subscribe"[^>]*>.*?</a>',
    '',
    content,
    flags=re.DOTALL
)

# 2. Add ONE desktop link
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
    r'<a id="nav-settings" class="nav-item" onclick="switchView\(\'settings\'\)">\s*<div class="nav-item-content">\s*<i class="fa-solid fa-gear"></i>\s*<span>Settings</span>\s*</div>\s*</a>', 
    desktop_link, 
    content
)

# 3. Add ONE mobile link
mobile_link = '''<a onclick="switchView('settings'); closeMobileMenu();">Settings</a>
          <a onclick="openSubscriptionModal(); closeMobileMenu();" style="color: #1FA15A; font-weight: bold; cursor: pointer;">Subscription</a>'''

content = re.sub(
    r'<a onclick="switchView\(\'settings\'\);\s*closeMobileMenu\(\);\s*">Settings</a>', 
    mobile_link, 
    content
)

# 4. Insert Modal HTML before <!-- CC MODAL -->
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
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">? Increased limits</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">? Premium support</li>
                    <li style="padding: 5px 0;">? Detailed analytics</li>
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
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">? Save $40 per year</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">? Increased limits</li>
                    <li style="padding: 5px 0; border-bottom: 1px solid #eeeff2;">? Premium support</li>
                    <li style="padding: 5px 0;">? Detailed analytics</li>
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

# 5. Add JS functions at end
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

print('Successfully updated admin.html with subscription modal.')
