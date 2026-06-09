import sys, re

with open('templates/admin.html', 'r', encoding='utf-8') as f:
    content = f.read()

new_block = '''<a onclick="switchView('settings'); closeMobileMenu();">Settings</a>
          <a href="/subscribe" style="color: #1FA15A; font-weight: bold;">Upgrade / Subscription</a>'''

content = re.sub(
    r'<a onclick="switchView\(\'settings\'\);\s*closeMobileMenu\(\);\s*">Settings</a>', 
    new_block, 
    content
)

with open('templates/admin.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Updated mobile menu in admin.html')
