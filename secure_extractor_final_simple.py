#!/usr/bin/env python3
"""
Final Version - Complete Regex Extraction System
"""

import re
import json
import datetime

class SecureRegexExtractor:
    def __init__(self):
        self.setup_patterns()
        self.dangerous_tags = ['script', 'iframe']
    
    def setup_patterns(self):
        # Existing patterns
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.phone_pattern = re.compile(r'(?:\(\d{3}\)|\d{3}[-.]?)\d{3}[-.]?\d{4}')
        self.url_pattern = re.compile(r'(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^ ]*)?')
        self.html_tag_pattern = re.compile(r'<(/)?([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?>')
        
        # NEW: Credit card pattern
        self.credit_card_pattern = re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')
    
    def luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13:
            return False
        
        total = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        
        return total % 10 == 0
    
    def extract_credit_cards(self, text: str):
        """Extract and validate credit cards."""
        cards = []
        for match in self.credit_card_pattern.finditer(text):
            card = re.sub(r'[ -]', '', match.group())
            if self.luhn_check(card):
                masked = card[:4] + 'X' * (len(card) - 8) + card[-4:]
                cards.append({
                    'number': card,
                    'masked': masked,
                    'valid': True,
                    'length': len(card)
                })
        return cards
    
    # Keep existing extraction methods
    def extract_emails(self, text: str):
        return self.email_pattern.findall(text)
    
    def extract_phones(self, text: str):
        phones = self.phone_pattern.findall(text)
        normalized = []
        for phone in phones:
            digits = re.sub(r'\D', '', phone)
            if len(digits) == 10:
                formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
                normalized.append(formatted)
        return normalized
    
    def extract_urls(self, text: str):
        urls = self.url_pattern.findall(text)
        return ['http://' + url if url.startswith('www.') else url for url in urls]
    
    def extract_html_tags(self, text: str):
        tags = []
        for match in self.html_tag_pattern.finditer(text):
            tag_name = match.group(2)
            if tag_name.lower() not in self.dangerous_tags:
                tags.append({
                    'tag': match.group(0),
                    'name': tag_name,
                    'is_closing': bool(match.group(1))
                })
        return tags
    
    def process_text(self, text: str):
        emails = self.extract_emails(text)
        phones = self.extract_phones(text)
        urls = self.extract_urls(text)
        html_tags = self.extract_html_tags(text)
        credit_cards = self.extract_credit_cards(text)  # NEW
        
        return {
            "data": {
                "emails": emails,
                "phone_numbers": phones,
                "urls": urls,
                "html_tags": html_tags,
                "credit_cards": credit_cards  # NEW
            },
            "statistics": {
                "total_emails": len(emails),
                "total_phones": len(phones),
                "total_urls": len(urls),
                "total_html_tags": len(html_tags),
                "total_credit_cards": len(credit_cards),  # NEW
                "total_items": len(emails) + len(phones) + len(urls) + len(html_tags) + len(credit_cards)
            },
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "version": "Final",
                "data_types": 5
            }
        }

def main():
    print("=" * 60)
    print("FINAL VERSION - Complete Extraction System")
    print("=" * 60)
    
    extractor = SecureRegexExtractor()
    
    try:
        with open('test_input.txt', 'r') as f:
            text = f.read()
        
        result = extractor.process_text(text)
        
        # Display results
        print(f"\nEmails: {result['statistics']['total_emails']}")
        for email in result['data']['emails']:
            print(f"  • {email}")
        
        print(f"\nPhones: {result['statistics']['total_phones']}")
        for phone in result['data']['phone_numbers']:
            print(f"  • {phone}")
        
        print(f"\nURLs: {result['statistics']['total_urls']}")
        for url in result['data']['urls']:
            print(f"  • {url}")
        
        print(f"\nHTML Tags: {result['statistics']['total_html_tags']}")
        for tag in result['data']['html_tags'][:5]:  # First 5 only
            tag_type = "Closing" if tag['is_closing'] else "Opening"
            print(f"  • {tag_type}: {tag['tag'][:40]}")
        
        print(f"\nCredit Cards: {result['statistics']['total_credit_cards']}")
        for card in result['data']['credit_cards']:
            print(f"  • {card['masked']} (Valid: {card['valid']}, Length: {card['length']})")
        
        # Save results
        with open('final_results.json', 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to 'final_results.json'")
        
        print(f"\nTotal items found: {result['statistics']['total_items']}")
        print(f"Data types extracted: {result['metadata']['data_types']}")
        
        print("\n" + "=" * 60)
        print("PROJECT COMPLETE! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
