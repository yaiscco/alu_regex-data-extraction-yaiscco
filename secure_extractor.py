#!/usr/bin/env python3
"""
Regex Data Extraction - Part 3
With Security and HTML Tag Extraction
"""

import re
import json
from typing import List, Dict, Any

class SecureRegexExtractor:
    def __init__(self):
        self.setup_patterns()
        self.max_input_size = 100000
        self.dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form']
    
    def setup_patterns(self):
        # Email pattern
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        # Phone pattern
        self.phone_pattern = re.compile(r'(?:\(\d{3}\)|\d{3}[-.]?)\d{3}[-.]?\d{4}')
        
        # URL pattern  
        self.url_pattern = re.compile(r'(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^ ]*)?')
        
        # HTML tag pattern - NEW in Part 3
        self.html_tag_pattern = re.compile(r'<(/)?([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?>')
    
    def validate_input_size(self, text: str) -> bool:
        return len(text) <= self.max_input_size
    
    def is_suspicious_email(self, email: str) -> bool:
        patterns = [r'\.{2,}', r'\.@', r'@\.', r'\.$', r'^\.']
        for pattern in patterns:
            if re.search(pattern, email):
                return True
        return False
    
    def is_dangerous_url(self, url: str) -> bool:
        patterns = [r'javascript:', r'data:', r'file:', r'\.exe$', r'\.js$']
        url_lower = url.lower()
        for pattern in patterns:
            if re.search(pattern, url_lower):
                return True
        return False
    
    def extract_emails(self, text: str) -> List[str]:
        emails = self.email_pattern.findall(text)
        return [email for email in emails if not self.is_suspicious_email(email)]
    
    def extract_phones(self, text: str) -> List[str]:
        phones = self.phone_pattern.findall(text)
        normalized = []
        for phone in phones:
            digits = re.sub(r'\D', '', phone)
            if len(digits) == 10:
                formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
                normalized.append(formatted)
        return normalized
    
    def extract_urls(self, text: str) -> List[str]:
        urls = self.url_pattern.findall(text)
        valid_urls = []
        for url in urls:
            if url.startswith('www.'):
                url = 'http://' + url
            if not self.is_dangerous_url(url):
                valid_urls.append(url)
        return valid_urls
    
    def extract_html_tags(self, text: str) -> List[Dict[str, str]]:
        tags = []
        for match in self.html_tag_pattern.finditer(text):
            full_tag = match.group(0)
            tag_name = match.group(2)
            is_closing = bool(match.group(1))
            if tag_name.lower() in self.dangerous_tags:
                continue
            tags.append({
                'tag': full_tag,
                'name': tag_name,
                'is_closing': is_closing
            })
        return tags
    
    def process_text(self, text: str) -> Dict[str, Any]:
        if not self.validate_input_size(text):
            return {"error": "Input too large"}
        
        emails = self.extract_emails(text)
        phones = self.extract_phones(text)
        urls = self.extract_urls(text)
        html_tags = self.extract_html_tags(text)
        
        return {
            "data": {
                "emails": emails,
                "phone_numbers": phones,
                "urls": urls,
                "html_tags": html_tags
            },
            "statistics": {
                "total_emails": len(emails),
                "total_phones": len(phones),
                "total_urls": len(urls),
                "total_html_tags": len(html_tags)
            }
        }

def main():
    print("=" * 60)
    print("REGEX EXTRACTION - PART 3")
    print("With Security & HTML Tags")
    print("=" * 60)
    
    extractor = SecureRegexExtractor()
    
    try:
        with open('test_input.txt', 'r') as file:
            text = file.read()
        
        result = extractor.process_text(text)
        
        print("\nRESULTS:")
        print("=" * 60)
        
        if "error" in result:
            print(f"Error: {result['error']}")
            return
        
        print(f"\nEmails found: {result['statistics']['total_emails']}")
        for email in result["data"]["emails"]:
            print(f"  • {email}")
        
        print(f"\nPhone numbers found: {result['statistics']['total_phones']}")
        for phone in result["data"]["phone_numbers"]:
            print(f"  • {phone}")
        
        print(f"\nURLs found: {result['statistics']['total_urls']}")
        for url in result["data"]["urls"]:
            print(f"  • {url}")
        
        print(f"\nHTML Tags found: {result['statistics']['total_html_tags']}")
        for tag in result["data"]["html_tags"]:
            tag_type = "Closing" if tag["is_closing"] else "Opening"
            print(f"  • {tag_type}: {tag['tag'][:50]}")
        
        # Save results
        with open('part3_results.json', 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to 'part3_results.json'")
        
        print("\n" + "=" * 60)
        print("PART 3 COMPLETE!")
        print("=" * 60)
        
    except FileNotFoundError:
        print("Error: test_input.txt not found")

if __name__ == "__main__":
    main()
