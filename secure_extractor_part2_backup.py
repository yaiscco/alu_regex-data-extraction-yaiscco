#!/usr/bin/env python3
"""
Secure Regular Expression Data Extraction System - Part 2: Basic Patterns
"""

import re
import json
from typing import List, Dict, Any

class SecureRegexExtractor:
    """Main class for extracting data using regex patterns"""
    
    def __init__(self):
        """Initialize the extractor with regex patterns"""
        print("Initializing SecureRegexExtractor...")
        self.setup_patterns()
    
    def setup_patterns(self):
        """Set up all regex patterns for data extraction"""
        print("Setting up regex patterns...")
        
        # Email pattern: finds email addresses
        self.email_pattern = re.compile(r"""
            \b                     # Word boundary
            [a-zA-Z0-9._%+-]+      # Local part (username)
            @                      @ symbol
            [a-zA-Z0-9.-]+         # Domain name
            \.                     # Dot before TLD
            [a-zA-Z]{2,}           # TLD (com, org, uk, etc.)
            \b                     # Word boundary
        """, re.VERBOSE | re.IGNORECASE)
        
        # Phone pattern: finds US/Canada phone numbers
        self.phone_pattern = re.compile(r"""
            \b                     # Word boundary
            (?:                    # Area code options:
              \(\d{3}\)            # (123)
              |                    # OR
              \d{3}[-.]?           # 123 or 123- or 123.
            )
            [-.]?                  # Optional separator
            \d{3}                  # First 3 digits
            [-.]?                  # Optional separator  
            \d{4}                  # Last 4 digits
            \b                     # Word boundary
        """, re.VERBOSE)
        
        # URL pattern: finds website addresses
        self.url_pattern = re.compile(r"""
            \b                     # Word boundary
            (?:https?://|www\.)    # http:// or https:// or www.
            [a-zA-Z0-9.-]+         # Domain name
            \.                     # Dot before TLD
            [a-zA-Z]{2,}           # TLD
            (?:/[a-zA-Z0-9_\-\.~:/?#\[\]@!$&'()*+,;=%]*)?  # Optional path
            \b                     # Word boundary
        """, re.VERBOSE | re.IGNORECASE)
        
        print("Patterns setup complete!")
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract all email addresses from text"""
        emails = self.email_pattern.findall(text)
        return emails
    
    def extract_phones(self, text: str) -> List[str]:
        """Extract all phone numbers from text"""
        phones = self.phone_pattern.findall(text)
        # Clean up the phone numbers
        cleaned_phones = []
        for phone in phones:
            # Remove non-digit characters
            digits = re.sub(r'\D', '', phone)
            # Format as (XXX) XXX-XXXX
            if len(digits) == 10:
                formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
                cleaned_phones.append(formatted)
        return cleaned_phones
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        urls = self.url_pattern.findall(text)
        # Ensure http:// prefix for www. URLs
        processed_urls = []
        for url in urls:
            if url.startswith('www.'):
                url = 'http://' + url
            processed_urls.append(url)
        return processed_urls
    
    def process_text(self, text: str) -> Dict[str, Any]:
        """Main function to process text and extract all data"""
        print(f"\nProcessing text of length: {len(text)} characters")
        
        # Extract all data types
        emails = self.extract_emails(text)
        phones = self.extract_phones(text)
        urls = self.extract_urls(text)
        
        # Create result dictionary
        result = {
            "emails": emails,
            "phone_numbers": phones,
            "urls": urls,
            "summary": {
                "total_emails": len(emails),
                "total_phones": len(phones),
                "total_urls": len(urls)
            }
        }
        
        return result

def main():
    """Main function to run the program"""
    print("=" * 50)
    print("REGEX DATA EXTRACTION SYSTEM - PART 2")
    print("=" * 50)
    
    # Create the extractor
    print("\nCreating extractor...")
    extractor = SecureRegexExtractor()
    
    try:
        # Read test input
        print("Reading test_input.txt...")
        with open('test_input.txt', 'r') as file:
            sample_text = file.read()
        
        # Process the text
        print("Extracting data from text...")
        result = extractor.process_text(sample_text)
        
        # Display results
        print("\n" + "=" * 50)
        print("EXTRACTION RESULTS")
        print("=" * 50)
        
        print("\n--- EMAILS FOUND ---")
        if result["emails"]:
            for email in result["emails"]:
                print(f"  • {email}")
        else:
            print("  No emails found")
        
        print("\n--- PHONE NUMBERS FOUND ---")
        if result["phone_numbers"]:
            for phone in result["phone_numbers"]:
                print(f"  • {phone}")
        else:
            print("  No phone numbers found")
        
        print("\n--- URLs FOUND ---")
        if result["urls"]:
            for url in result["urls"]:
                print(f"  • {url}")
        else:
            print("  No URLs found")
        
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)
        print(f"Total emails: {result['summary']['total_emails']}")
        print(f"Total phone numbers: {result['summary']['total_phones']}")
        print(f"Total URLs: {result['summary']['total_urls']}")
        
        print("\nPart 2 complete! Ready for Part 3 (security features).")
        
        # Also save results to JSON file
        with open('extraction_results.json', 'w') as json_file:
            json.dump(result, json_file, indent=2)
        print("\nResults saved to 'extraction_results.json'")
        
    except FileNotFoundError:
        print("\nError: test_input.txt not found!")
        print("Make sure test_input.txt exists in the same directory")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
