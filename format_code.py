#!/usr/bin/env python3
"""
Simple code formatter to fix basic formatting issues
"""

import os
import re

def format_file(filepath):
    """Format a Python file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Fix basic formatting issues
    # Fix quotes
    content = re.sub(r"'([^']*)'", r'"\1"', content)
    
    # Fix trailing commas in function calls
    content = re.sub(r',\s*\)', ')', content)
    
    # Add newline at end of file
    if not content.endswith('\n'):
        content += '\n'
    
    with open(filepath, 'w') as f:
        f.write(content)

def main():
    """Main function"""
    src_dir = 'src'
    if os.path.exists(src_dir):
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    print(f"Formatting {filepath}")
                    format_file(filepath)

if __name__ == "__main__":
    main()