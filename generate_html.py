import markdown
import sys

# Read the markdown
with open('research-paper.md', 'r', encoding='utf-8') as f:
    text = f.read()

# Convert to HTML with some basic extensions for tables and formatting
html_body = markdown.markdown(text, extensions=['tables', 'fenced_code'])

# Wrap it in a nice HTML template so it looks good when printed to PDF
html_structure = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Research Paper</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.6;
        color: #333;
        max-width: 850px;
        margin: 0 auto;
        padding: 40px;
    }}
    h1, h2, h3 {{ border-bottom: 1px solid #eaecef; padding-bottom: .3em; }}
    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
    th, td {{ border: 1px solid #dfe2e5; padding: 6px 13px; text-align: left; }}
    th {{ background-color: #f6f8fa; }}
    code {{ background-color: #f6f8fa; padding: .2em .4em; border-radius: 3px; font-family: monospace; }}
    pre code {{ display: block; padding: 16px; overflow-x: auto; }}
</style>
</head>
<body>
{html_body}
</body>
</html>
"""

# Write the final HTML file
with open('research-paper.html', 'w', encoding='utf-8') as f:
    f.write(html_structure)

print("Conversion complete.")
