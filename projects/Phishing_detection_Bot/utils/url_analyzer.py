"""
URL analysis module for phishing detection.

This module provides functions to analyze URLs for phishing indicators,
including suspicious domains, redirects, typosquatting, and other common
techniques used in phishing attempts.
"""

import re
import logging
import json
import os
import socket
from typing import Dict, List, Any, Optional, Union, NamedTuple, Tuple
from dataclasses import dataclass, field
import urllib.parse
import ipaddress
from datetime import datetime, timedelta
import requests
import whois
from ssl import create_default_context, SSLError
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants for URL analysis
COMMON_PORTS = {80, 443, 8080, 8443}  # Common legitimate web ports

# High-risk TLDs often used in phishing
SUSPICIOUS_TLDS = {
    'tk': 'Tokelau - commonly abused free TLD',
    'ml': 'Mali - commonly abused free TLD',
    'ga': 'Gabon - commonly abused free TLD',
    'cf': 'Central African Republic - commonly abused free TLD',
    'gq': 'Equatorial Guinea - commonly abused free TLD',
    'xyz': 'Generic TLD with high abuse rate',
    'info': 'Generic TLD with higher than average abuse rate',
    'top': 'Generic TLD with higher than average abuse rate'
}

# Country TLDs that may require higher scrutiny based on cybercrime statistics
HIGHER_SCRUTINY_COUNTRY_CODES = {
    'ru', 'cn', 'ir', 'kp', 'su', 'ws', 'to'
}

# Legitimate but restricted TLDs that are less likely to be used in phishing
RESTRICTED_TLDS = {
    'gov', 'edu', 'mil', 'int', 'museum', 'aero', 'post', 'jobs', 'cat', 'coop'
}

# New generic TLDs (not automatically suspicious but noted for awareness)
NEW_GTLDS = {
    'app', 'dev', 'tech', 'online', 'site', 'website', 'blog', 'shop', 'store', 
    'cloud', 'digital', 'network', 'web', 'design', 'host', 'hosting', 'space'
}

# Commonly impersonated brands in phishing attacks
IMPERSONATED_BRANDS = [
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 'facebook', 
    'instagram', 'twitter', 'linkedin', 'bank', 'wellsfargo', 'chase', 'citi',
    'bankofamerica', 'dropbox', 'office365', 'outlook', 'icloud', 'gmail', 
    'yahoo', 'ebay', 'walmart', 'usps', 'fedex', 'dhl', 'ups'
]

# Weights for different URL factors in scoring
FACTOR_WEIGHTS = {
    "tld": {
        "suspicious": 0.35,
        "higher_scrutiny": 0.15,
        "new_gtld": 0.05
    },
    "domain": {
        "typosquatting": 0.35,
        "impersonation": 0.4,
        "numeric_ip": 0.4,
        "excessive_subdomains": 0.25,
        "brand_subdomain": 0.3,
        "long_domain": 0.15
    },
    "path": {
        "suspicious_keywords": 0.2,
        "excessive_length": 0.1
    },
    "connection": {
        "http_only": 0.25,
        "invalid_cert": 0.35,
        "redirect": 0.3,
        "suspicious_port": 0.25
    },
    "reputation": {
        "new_domain": 0.35,
        "suspicious_registrar": 0.25,
        "blacklisted": 0.5
    }
}

# Suspicious terms often found in phishing URLs
SUSPICIOUS_URL_TERMS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'account', 'password',
    'confirm', 'update', 'banking', 'authenticate', 'wallet', 'validation',
    'suspend', 'unusual', 'activity', 'access', 'limited', 'unlock', 'recover'
]


# Data Structures for Analysis Results
@dataclass
class URLAnalysisResult:
    """Result of URL analysis for phishing detection."""
    url: str
    score: float = 0.0
    is_suspicious: bool = False
    suspicious_elements: List[str] = field(default_factory=list)
    safe_elements: List[str] = field(default_factory=list)
    redirect_info: Optional[Dict[str, Any]] = None
    domain_info: Optional[Dict[str, Any]] = None
    components: Dict[str, Any] = field(default_factory=dict)


def parse_url(url: str) -> Dict[str, Any]:
    """
    Parse URL into its components with additional checks for validity.
    
    Args:
        url: The URL to parse
        
    Returns:
        Dictionary containing components or error information
    """
    if not url:
        return {"error": "Empty URL"}
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Parse the URL
        parsed = urllib.parse.urlparse(url)
        
        # Check if valid
        if not parsed.netloc:
            return {"error": "Invalid URL format: missing domain", "valid": False}
        
        return {
            "parsed": parsed,
            "valid": True
        }
    except Exception as e:
        logger.error(f"Error parsing URL: {str(e)}")
        return {"error": str(e), "valid": False}


def extract_url_components(url: str) -> Dict[str, Any]:
    """
    Extract and analyze components from a URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary of URL components with additional derived data
    """
    parse_result = parse_url(url)
    
    if not parse_result.get("valid", False):
        return {"error": parse_result.get("error", "Invalid URL")}
    
    parsed = parse_result["parsed"]
    
    # Extract base components
    components = {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "params": parsed.params,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }
    
    # Extract netloc components (domain, subdomain, port)
    try:
        # Extract port if present
        port = None
        if ':' in parsed.netloc:
            domain_part, port_part = parsed.netloc.split(':', 1)
            components["netloc"] = domain_part
            try:
                port = int(port_part)
                components["port"] = port
            except ValueError:
                components["port_error"] = "Invalid port"
        else:
            domain_part = parsed.netloc
        
        # Check if IP address
        try:
            ipaddress.ip_address(domain_part)
            components["is_ip"] = True
            components["domain"] = domain_part
        except ValueError:
            components["is_ip"] = False
            
            # Extract domain parts
            domain_parts = domain_part.split('.')
            
            if len(domain_parts) >= 2:
                # Extract TLD
                tld = domain_parts[-1]
                components["tld"] = tld
                
                # Handle country code second-level domains (e.g., co.uk, com.au)
                if len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'edu'] and len(domain_parts[-1]) == 2:
                    components["domain"] = f"{domain_parts[-3]}.{domain_parts[-2]}.{domain_parts[-1]}"
                    if len(domain_parts) > 3:
                        components["subdomain"] = '.'.join(domain_parts[:-3])
                else:
                    # Standard domain handling
                    components["domain"] = f"{domain_parts[-2]}.{domain_parts[-1]}"
                    if len(domain_parts) > 2:
                        components["subdomain"] = '.'.join(domain_parts[:-2])
    
    except Exception as e:
        components["parsing_error"] = str(e)
    
    # Get query parameters as a dictionary
    components["query_params"] = dict(urllib.parse.parse_qsl(parsed.query))
    
    # Path analysis
    components["path_segments"] = [segment for segment in parsed.path.split('/') if segment]
    
    return components


def analyze_tld(url: str) -> Dict[str, Any]:
    """
    Analyze the TLD (Top Level Domain) of a URL for risk assessment.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary with TLD analysis results
    """
    result = {
        "suspicious": False,
        "reason": "",
        "tld": "",
    }
    
    components = extract_url_components(url)
    
    # Check if components extraction was successful
    if "error" in components:
        result["suspicious"] = True
        result["reason"] = f"URL parsing error: {components['error']}"
        return result
    
    # If IP address is used instead of domain, mark as suspicious
    if components.get("is_ip", False):
        result["suspicious"] = True
        result["reason"] = "IP address used instead of domain name"
        return result
    
    # Extract TLD
    tld = components.get("tld", "").lower()
    if not tld:
        result["suspicious"] = True
        result["reason"] = "No TLD found"
        return result
    
    result["tld"] = tld
    
    # Check if TLD is in the suspicious list
    if tld in SUSPICIOUS_TLDS:
        result["suspicious"] = True
        result["reason"] = SUSPICIOUS_TLDS[tld]
    
    # Check if TLD requires higher scrutiny
    if tld in HIGHER_SCRUTINY_COUNTRY_CODES:
        result["higher_scrutiny"] = True
        result["reason"] = f"TLD from region requiring higher scrutiny: .{tld}"
    
    # Check if it's a restricted TLD
    if tld in RESTRICTED_TLDS:
        result["restricted"] = True
        result["reason"] = f"Restricted TLD: .{tld}"
    
    # Check if it's a new gTLD
    if tld in NEW_GTLDS:
        result["new_gtld"] = True
        result["reason"] = f"New generic TLD: .{tld}"
    
    # Check if it's a very uncommon TLD
    common_tlds = {"com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "au", "ca", "de", "jp", "fr", "it", "nl", "ru", "br", "es", "eu"}
    if tld not in common_tlds and tld not in SUSPICIOUS_TLDS and tld not in RESTRICTED_TLDS and tld not in NEW_GTLDS:
        result["rare"] = True
        result["reason"] = f"Uncommon TLD: .{tld}"
    
    return result


def detect_suspicious_patterns(url: str) -> List[str]:
    """
    Detect suspicious patterns in a URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        List of suspicious patterns found
    """
    patterns = []
    
    try:
        # Check for suspicious keywords
        suspicious_keywords = [
            'secure', 'verify', 'update', 'confirm', 'account', 'login',
            'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'urgent', 'suspend', 'expire', 'limited', 'click', 'here'
        ]
        
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                patterns.append(f"Contains suspicious keyword: {keyword}")
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.ly']
        for shortener in shorteners:
            if shortener in url_lower:
                patterns.append(f"Uses URL shortener: {shortener}")
        
        # Check for suspicious characters
        if any(char in url for char in ['%', '&', '=', '?']) and len([char for char in url if char in ['%', '&', '=', '?']]) > 5:
            patterns.append("Contains excessive special characters")
        
        # Check for IP addresses
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            patterns.append("Uses IP address instead of domain")
            
    except Exception as e:
        patterns.append(f"Error analyzing patterns: {str(e)}")
    
    return patterns


def check_domain_reputation(domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Check the reputation of a domain using various indicators.
    
    Args:
        domain: The domain to check
        api_key: Optional API key for external reputation services
        
    Returns:
        Dictionary with reputation information
    """
    result = {
        "domain": domain,
        "suspicious": False,
        "reasons": []
    }
    
    try:
        # Skip IP addresses
        try:
            ipaddress.ip_address(domain)
            result["suspicious"] = True
            result["reasons"].append("Using IP address instead of domain name")
            return result
        except ValueError:
            pass
        
        # Get WHOIS information
        try:
            w = whois.whois(domain)
            
            # Check domain age (new domains are more suspicious)
            if w.creation_date:
                # Handle both list and single datetime
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if isinstance(creation_date, datetime):
                    domain_age = datetime.now() - creation_date
                    if domain_age < timedelta(days=60):
                        result["suspicious"] = True
                        result["reasons"].append(f"Recent registration: {domain_age.days} days old")
                        
                    result["domain_age_days"] = domain_age.days
                    result["creation_date"] = creation_date.isoformat()
            
            # Check registrar (some registrars are associated with more abuse)
            if w.registrar:
                result["registrar"] = w.registrar
                suspicious_registrars = ["NAMECHEAP", "NANJING", "NICENIC", "BIZCN", "REGRU", 
                                        "ONLINENIC", "DYNADOT", "INTERNET.BS", "ERANET", "ALIBABA"]
                
                for suspicious_reg in suspicious_registrars:
                    if suspicious_reg.upper() in w.registrar.upper():
                        result["suspicious"] = True
                        result["reasons"].append(f"Suspicious registrar: {w.registrar}")
                        break
                    
        except Exception as e:
            logger.warning(f"Error checking WHOIS for {domain}: {str(e)}")
            # Don't flag as suspicious just because WHOIS check failed
            result["whois_error"] = str(e)
        
        # Try to perform a DNS lookup to verify domain exists
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            result["suspicious"] = True
            result["reasons"].append("Domain does not resolve to an IP address")
        
    except Exception as e:
        logger.error(f"Error in domain reputation check: {str(e)}")
        result["error"] = str(e)
    
    return result


def analyze_url(url: str) -> URLAnalysisResult:
    """
    Main function to analyze a URL for phishing indicators.
    
    Args:
        url: The URL to analyze
        
    Returns:
        URLAnalysisResult object with analysis results
    """
    result = URLAnalysisResult(url=url)
    
    try:
        # Extract URL components
        components = extract_url_components(url)
        result.components = components
        
        if "error" in components:
            result.suspicious_elements.append(f"URL parsing error: {components['error']}")
            result.score = 80.0
            result.is_suspicious = True
            return result
        
        # Analyze TLD
        tld_analysis = analyze_tld(url)
        if tld_analysis.get("suspicious", False):
            result.suspicious_elements.append(f"Suspicious TLD: {tld_analysis.get('reason', '')}")
            result.score += 35
        
        # Detect suspicious patterns
        patterns = detect_suspicious_patterns(url)
        result.suspicious_elements.extend(patterns)
        
        # Calculate score based on patterns
        if patterns:
            result.score += len(patterns) * 15
        
        # Check domain reputation if available
        domain = components.get("domain", "")
        if domain:
            reputation = check_domain_reputation(domain)
            if reputation.get("suspicious", False):
                result.suspicious_elements.extend(reputation.get("reasons", []))
                result.score += 25
        
        # Determine if suspicious
        result.is_suspicious = result.score >= 30
        
        # Cap score at 100
        result.score = min(result.score, 100.0)
        
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {str(e)}")
        result.suspicious_elements.append(f"Analysis error: {str(e)}")
        result.score = 50.0
        result.is_suspicious = True
    
    return result


if __name__ == "__main__":
    # Example usage
    test_url = "http://example.com"
    try:
        result = analyze_url(test_url)
        print(f"URL: {result.url}")
        print(f"Suspicious: {result.is_suspicious}")
        print(f"Score: {result.score}")
        print("Suspicious elements:")
        for element in result.suspicious_elements:
            print(f"  - {element}")
        print("Safe elements:")
        for element in result.safe_elements:
            print(f"  - {element}")
    except Exception as e:
        print(f"Error analyzing URL: {e}")


def calculate_url_score(url: str) -> Dict[str, Any]:
    """
    Calculate a phishing suspicion score for a URL based on multiple factors.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary with score and contributing factors
    """
    result = {
        "score": 0.0,
        "factors": []
    }
    
    try:
        score = 0.0
        total_weight = 0.0
        factors = []
        
        # Get URL components
        components = extract_url_components(url)
        if "error" in components:
            factors.append({
                "type": "error",
                "description": f"URL parsing error: {components['error']}",
                "impact": 0.8
            })
            result["score"] = 0.8
            result["factors"] = factors
            return result
        
        # Check scheme (HTTP vs HTTPS)
        scheme = components.get("scheme", "")
        if scheme == "http":
            score += FACTOR_WEIGHTS["connection"]["http_only"]
            total_weight += FACTOR_WEIGHTS["connection"]["http_only"]
            factors.append({
                "type": "risk",
                "description": "Using insecure HTTP protocol",
                "impact": FACTOR_WEIGHTS["connection"]["http_only"]
            })
        elif scheme == "https":
            factors.append({
                "type": "safe",
                "description": "Using secure HTTPS protocol",
                "impact": -0.1
            })
        
        # Check for suspicious patterns
        suspicious_patterns = detect_suspicious_patterns(url)
        if suspicious_patterns:
            for pattern in suspicious_patterns:
                # Determine impact based on pattern type
                impact = 0.2  # Default impact
                
                if "IP address" in pattern:
                    impact = FACTOR_WEIGHTS["domain"]["numeric_ip"]
                elif "unusual port" in pattern:
                    impact = FACTOR_WEIGHTS["connection"]["suspicious_port"]
                elif "Excessive subdomains" in pattern:
                    impact = FACTOR_WEIGHTS["domain"]["excessive_subdomains"]
                elif "Brand name in subdomain" in pattern:
                    impact = FACTOR_WEIGHTS["domain"]["brand_subdomain"]
                elif "typosquatting" in pattern:
                    impact = FACTOR_WEIGHTS["domain"]["typosquatting"]
                elif "Brand name with additional domain" in pattern:
                    impact = FACTOR_WEIGHTS["domain"]["impersonation"]
                
                score += impact
                total_weight += impact
                factors.append({
                    "type": "risk",
                    "description": pattern,
                    "impact": impact
                })
        
        # Check TLD
        tld_result = analyze_tld(url)
        if tld_result.get("suspicious", False):
            impact = FACTOR_WEIGHTS["tld"]["suspicious"]
            score += impact
            total_weight += impact
            factors.append({
                "type": "risk",
                "description": f"Suspicious TLD: .{tld_result.get('tld', '')} - {tld_result.get('reason', '')}",
                "impact": impact
            })
        elif tld_result.get("higher_scrutiny", False):
            impact = FACTOR_WEIGHTS["tld"]["higher_scrutiny"]
            score += impact
            total_weight += impact
            factors.append({
                "type": "risk",
                "description": f"TLD requiring higher scrutiny: .{tld_result.get('tld', '')}",
                "impact": impact
            })
        elif tld_result.get("new_gtld", False):
            impact = FACTOR_WEIGHTS["tld"]["new_gtld"]
            score += impact
            total_weight += impact
            factors.append({
                "type": "risk",
                "description": f"New generic TLD: .{tld_result.get('tld', '')}",
                "impact": impact
            })
        elif tld_result.get("restricted", False):
            # Restricted TLDs are typically more trustworthy
            factors.append({
                "type": "safe",
                "description": f"Restricted TLD: .{tld_result.get('tld', '')}",
                "impact": -0.15
            })
        
        # Normalize score if we have factors to consider
        if total_weight > 0:
            normalized_score = score / max(total_weight, 1.0)
            # Cap at 1.0
            normalized_score = min(normalized_score, 1.0)
        else:
            normalized_score = 0.0
        
        result["score"] = normalized_score
        result["factors"] = factors
        
    except Exception as e:
        logger.error(f"Error calculating URL score: {str(e)}")
        result["error"] = str(e)
    
    return result


