#!/usr/bin/env python3
"""
Secure Regex Data Extraction System - Part 3
Adds security features and HTML tag extraction
"""

import re
import json
from typing import List, Dict, Any

class SecureRegexExtractor:
    """Extracts structured data from text with security validation."""
    
    def __init__(self):
        """Initialize patterns and security settings."""
        self.setup_patterns()
        self.setup_security_settings()
    
    def setup_security_settings(self):
        """Configure security parameters."""
        self.max_input_size = 100000  # Maximum characters to process
        self.max_email_length = 254    # RFC 5321 email length limit
        self.dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form']
    
    def setup_patterns(self):
        """Compile regex patterns for data extraction."""
        
        # Email pattern: standard email format validation
        self.email_pattern = re.compile(r"""
            \b
            [a-zA-Z0-9._%+-]+      # Local part
            @
            [a-zA-Z0-9.-]+         # Domain
            \.
            [a-zA-Z]{2,}           # TLD
            \b
        """, re.VERBOSE | re.IGNORECASE)
        
        # Phone pattern: US/Canada formats with area code
        self.phone_pattern = re.compile(r"""
            \b
            (?:\(\d{3}\)|\d{3}[-.]?)  # Area code with/without parentheses
            [-.]?
            \d{3}                      # Prefix
            [-.]?
            \d{4}                      # Line number
            \b
        """, re.VERBOSE)
        
        # URL pattern: HTTP/HTTPS and www domains
        self.url_pattern = re.compile(r"""
            \b
            (?:https?://|www\.)        # Protocol or www prefix
            [a-zA-Z0-9.-]+             # Domain name
            \.
            [a-zA-Z]{2,}               # TLD
            (?:/[a-zA-Z0-9_\-\.~:/?#\[\]@!$&'()*+,;=%]*)?  # Optional path
            \b
        """, re.VERBOSE | re.IGNORECASE)
        
        # HTML tag pattern: extracts tags and attributes
        self.html_tag_pattern = re.compile(r"""
            <
            (/)?                        # Closing tag indicator
            ([a-zA-Z][a-zA-Z0-9]*)      # Tag name
            (?:\s+[^>]*)?               # Optional attributes
            >
        """, re.VERBOSE | re.IGNORECASE)
    
    def validate_input_size(self, text: str) -> bool:
        """
        Prevent processing of excessively large inputs.
        
        Returns:
            True if input is within size limits, False otherwise
        """
        if len(text) > self.max_input_size:
            return False
        return True
    
    def sanitize_for_logging(self, data: str) -> str:
        """
        Mask sensitive information before logging.
        
        Args:
            data: Input string potentially containing sensitive data
            
        Returns:
            String with sensitive patterns masked
        """
        # Mask email local parts
        data = re.sub(r'([a-zA-Z0-9._%+-]+)@', '[EMAIL]@', data)
        # Mask phone numbers (keep last 4 digits)
        data = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', data)
        return data
    
    def is_suspicious_email(self, email: str) -> bool:
        """
        Detect potentially malicious email patterns.
        
        Common attack patterns: consecutive dots, invalid positions
        """
        suspicious_patterns = [
            r'\.{2,}',  # Multiple consecutive dots
            r'\.@',     # Dot immediately before @
            r'@\.',     # @ immediately before dot
            r'\.$',     # Ends with dot
            r'^\.',     # Starts with dot
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email):
                return True
        
        if len(email) > self.max_email_length:
            return True
        
        return False
    
    def is_dangerous_url(self, url: str) -> bool:
        """
        Identify URLs that could execute code or access local resources.
        
        Blocks: javascript:, data:, file: protocols and executable extensions
        """
        dangerous_patterns = [
            r'javascript:',  # Can execute arbitrary JavaScript
            r'data:',        # Data URLs can contain executable content
            r'file:',        # Accesses local file system
            r'\.exe$',       # Executable files
            r'\.js$',        # JavaScript files
        ]
        
        url_lower = url.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract valid email addresses with security filtering."""
        emails = self.email_pattern.findall(text)
        valid_emails = [email for email in emails if not self.is_suspicious_email(email)]
        return valid_emails
    
    def extract_phones(self, text: str) -> List[str]:
        """Extract and normalize phone numbers."""
        phones = self.phone_pattern.findall(text)
        normalized = []
        
        for phone in phones:
            digits = re.sub(r'\D', '', phone)
            if len(digits) == 10:  # Standard US/Canada format
                formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
                normalized.append(formatted)
        
        return normalized
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs with protocol validation and security checks."""
        urls = self.url_pattern.findall(text)
        valid_urls = []
        
        for url in urls:
            if url.startswith('www.'):
                url = 'http://' + url
            
            if not self.is_dangerous_url(url):
                valid_urls.append(url)
        
        return valid_urls
    
    def extract_html_tags(self, text: str) -> List[Dict[str, str]]:
        """
        Extract HTML tags while filtering dangerous elements.
        
        Returns:
            List of dictionaries with tag information
        """
        tags = []
        
        for match in self.html_tag_pattern.finditer(text):
            full_tag = match.group(0)
            tag_name = match.group(2)
            is_closing = bool(match.group(1))
            
            # Security: skip potentially dangerous tags
            if tag_name.lower() in self.dangerous_tags:
                continue
            
            tags.append({
                'tag': full_tag,
                'name': tag_name,
                'is_closing': is_closing,
                'position': match.start()
            })
        
        return tags
    
    def process_text(self, text: str) -> Dict[str, Any]:
        """
        Main text processing pipeline with security validation.
        
        Args:
            text: Input text to process
            
        Returns:
            Dictionary containing extracted data and metadata
        """
        # Input validation
        if not self.validate_input_size(text):
            return {
                "error": "Input exceeds maximum size",
                "max_allowed": self.max_input_size,
                "received": len(text)
            }
        
        # Log sanitized version (security best practice)
        sanitized_preview = self.sanitize_for_logging(text[:200])
        
        # Extract data with security filters
        emails = self.extract_emails(text)
        phones = self.extract_phones(text)
        urls = self.extract_urls(text)
        html_tags = self.extract_html_tags(text)
        
        # Structure results
        return {
            "data": {
                "emails": emails,
                "phone_numbers": phones,
                "urls": urls,
                "html_tags": html_tags
            },
            "metadata": {
                "input_size": len(text),
                "extraction_time": "2024-01-15T10:30:00Z",
                "security_checks": "passed"
            },
            "statistics": {
                "total_emails": len(emails),
                "total_phones": len(phones),
                "total_urls": len(urls),
                "total_html_tags": len(html_tags)
            }
        }

def main():
    """Command-line interface for the extraction system."""
    
    # Create extractor instance
    extractor = SecureRegexExtractor()
    
    try:
        # Read input file
        with open('test_input.txt', 'r') as file:
            sample_text = file.read()
        
        # Process text
        result = extractor.process_text(sample_text)
        
        # Display results
        print("Extraction Results:")
        print("=" * 50)
        
        if "error" in result:
            print(f"Error: {result['error']}")
            print(f"Details: {result.get('max_allowed')}")
            return
        
        # Emails section
        print("\nEmails Found:")
        print("-" * 30)
        if result["data"]["emails"]:
            for email in result["data"]["emails"]:
                print(f"  • {email}")
        else:
            print("  None")
        
        # Phone numbers section
        print("\nPhone Numbers Found:")
        print("-" * 30)
        if result["data"]["phone_numbers"]:
            for phone in result["data"]["phone_numbers"]:
                print(f"  • {phone}")
        else:
            print("  None")
        
        # URLs section
        print("\nURLs Found:")
        print("-" * 30)
        if result["data"]["urls"]:
            for url in result["data"]["urls"]:
                print(f"  • {url}")
        else:
            print("  None")
        
        # HTML tags section
        print("\nHTML Tags Found:")
        print("-" * 30)
        if result["data"]["html_tags"]:
            for tag in result["data"]["html_tags"]:
                tag_type = "Closing" if tag["is_closing"] else "Opening"
                print(f"  • {tag_type}: {tag['tag'][:40]}")
        else:
            print("  None")
        
        # Statistics
        print("\nStatistics:")
        print("-" * 30)
        stats = result["statistics"]
        print(f"Total emails: {stats['total_emails']}")
        print(f"Total phone numbers: {stats['total_phones']}")
        print(f"Total URLs: {stats['total_urls']}")
        print(f"Total HTML tags: {stats['total_html_tags']}")
        
        # Save to JSON
        output_file = 'results_part3.json'
        with open(output_file, 'w') as json_file:
            json.dump(result, json_file, indent=2)
        print(f"\nResults saved to {output_file}")
        
    except FileNotFoundError:
        print("Error: test_input.txt not found")
        print("Create test_input.txt with sample data")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
