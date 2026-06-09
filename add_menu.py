import sys, re

with open('templates/admin.html', 'r', encoding='utf-8') as f:
    content = f.read()

new_block = '''<a id="nav-settings" class="nav-item" onclick="switchView('settings')">
          <div class="nav-item-content">
            <i class="fa-solid fa-gear"></i>
            <span>Settings</span>
          </div>
        </a>

        <a href="/subscribe" class="nav-item" style="color: #1FA15A; font-weight: bold;">
          <div class="nav-item-content">
            <i class="fa-solid fa-credit-card"></i>
            <span>Upgrade / Subscription</span>
          </div>
        </a>'''

content = re.sub(
    r'<a id="nav-settings" class="nav-item" onclick="switchView\(\'settings\'\)">\s*<div class="nav-item-content">\s*<i class="fa-solid fa-gear"></i>\s*<span>Settings</span>\s*</div>\s*</a>', 
    new_block, 
    content
)

with open('templates/admin.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Updated admin.html')
