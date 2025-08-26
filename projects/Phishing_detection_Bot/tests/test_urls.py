import pytest
import sys
import os
import re
from unittest.mock import MagicMock, patch
import urllib.parse
import requests
import json
from ipaddress import ip_address

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.url_analyzer import (
    analyze_url,
    check_domain_reputation,
    extract_url_components,
    detect_suspicious_patterns,
    calculate_url_score,
    check_redirects,
    analyze_tld
)


# Fixtures
@pytest.fixture
def phishing_urls():
    """Sample phishing URLs for testing"""
    return [
        "http://paypal-secure.signin.com-id.me/verification",
        "https://bankofamerica.security-check.com/login.php",
        "http://accounts.google.com.verify.malicious-site.com/reset",
        "https://www.amaz0n.com/account/signin",
        "http://secure-banking.com.suspicious.net/login",
        "https://www.dropb0x.com/share/document",
        "http://tracking-your-parcel.com/?id=12345&redirect=true",
        "https://payment-secure-gateway.info/checkout",
        "http://facebook-login.secretsite.ru/verify",
        "https://apple-icloud-verify.tk/signin"
    ]


@pytest.fixture
def legitimate_urls():
    """Sample legitimate URLs for testing"""
    return [
        "https://www.paypal.com/signin",
        "https://www.bankofamerica.com/login",
        "https://accounts.google.com/login",
        "https://www.amazon.com/your-account",
        "https://www.facebook.com/login",
        "https://www.apple.com/icloud",
        "https://www.microsoft.com/en-us/account",
        "https://twitter.com/login",
        "https://www.instagram.com/accounts/login",
        "https://www.netflix.com/login"
    ]


@pytest.fixture
def url_components():
    """Sample extracted URL components for testing"""
    return {
        "https://sub.example.com:8080/path/page.php?id=123&user=test#section": {
            "scheme": "https",
            "netloc": "sub.example.com:8080",
            "path": "/path/page.php",
            "params": "",
            "query": "id=123&user=test",
            "fragment": "section",
            "domain": "example.com",
            "subdomain": "sub",
            "tld": "com",
            "port": 8080
        },
        "http://paypal-secure.signin.com-id.me/verification": {
            "scheme": "http",
            "netloc": "paypal-secure.signin.com-id.me",
            "path": "/verification",
            "params": "",
            "query": "",
            "fragment": "",
            "domain": "signin.com-id.me",
            "subdomain": "paypal-secure",
            "tld": "me",
            "port": None
        }
    }


@pytest.fixture
def mock_safebrowsing_api():
    """Mock response for Safe Browsing API"""
    def _create_mock(is_threat=False):
        mock_response = MagicMock()
        if is_threat:
            mock_response.json.return_value = {
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": "http://malicious-url.com"},
                        "cacheDuration": "300s",
                        "threatEntryType": "URL"
                    }
                ]
            }
        else:
            mock_response.json.return_value = {}
        
        mock_response.status_code = 200
        return mock_response
    
    return _create_mock


@pytest.fixture
def mock_whois_response():
    """Mock response for WHOIS API"""
    def _create_mock(creation_date=None, registrar=None, is_error=False):
        mock_response = MagicMock()
        
        if is_error:
            mock_response.json.side_effect = Exception("WHOIS API error")
            return mock_response
        
        if not creation_date:
            creation_date = "2010-01-01T00:00:00Z"  # Default to old domain
            
        if not registrar:
            registrar = "Legitimate Registrar Inc."
            
        mock_response.json.return_value = {
            "domain_name": "example.com",
            "creation_date": creation_date,
            "updated_date": "2023-01-01T00:00:00Z",
            "expiration_date": "2025-01-01T00:00:00Z",
            "registrar": registrar,
            "registrant": {
                "name": "Domain Owner",
                "email": "owner@example.com"
            }
        }
        
        mock_response.status_code = 200
        return mock_response
    
    return _create_mock


# Tests for URL Pattern Detection
class TestURLPatternDetection:
    
    def test_detect_suspicious_patterns(self):
        """Test detection of suspicious patterns in URLs"""
        suspicious_patterns = [
            "https://paypal.secure-login.com/signin",  # Brand in subdomain
            "https://paypal-secure-signin.com/login",  # Brand with hyphens
            "https://www.paypa1.com/account",         # Typosquatting with number
            "https://www.paypal.com.suspicious.org/",  # Brand with appended domain
            "https://www.secure-paypal-login.com/",    # Brand in middle of domain
            "http://paypol.com/login",                # Misspelled brand
        ]
        
        for url in suspicious_patterns:
            patterns = detect_suspicious_patterns(url)
            assert len(patterns) > 0, f"Failed to detect pattern in {url}"
    
    def test_legitimate_url_patterns(self):
        """Test that legitimate URLs don't trigger false positives"""
        legitimate_patterns = [
            "https://www.paypal.com/signin",
            "https://login.microsoft.com/",
            "https://accounts.google.com/signin",
            "https://www.amazon.com/dp/B0CTDVM3F6/"
        ]
        
        for url in legitimate_patterns:
            patterns = detect_suspicious_patterns(url)
            assert len(patterns) == 0, f"False positive pattern detection in {url}"
    
    def test_numeric_ip_detection(self):
        """Test detection of numeric IP addresses instead of domains"""
        ip_urls = [
            "http://192.168.1.1/login",
            "http://127.0.0.1:8080/admin",
            "https://8.8.8.8/search",
            "http://169.254.169.254/signin"
        ]
        
        for url in ip_urls:
            patterns = detect_suspicious_patterns(url)
            assert any("IP address" in pattern for pattern in patterns), f"Failed to detect IP address in {url}"
    
    def test_unusual_port_detection(self):
        """Test detection of unusual ports in URLs"""
        unusual_port_urls = [
            "http://example.com:1337/login",
            "https://secure-bank.com:8080/auth",
            "http://login-service.com:25/signin"
        ]
        
        for url in unusual_port_urls:
            patterns = detect_suspicious_patterns(url)
            assert any("unusual port" in pattern.lower() for pattern in patterns), f"Failed to detect unusual port in {url}"


# Tests for Domain Validation
class TestDomainValidation:
    
    @patch("requests.get")
    def test_domain_age_validation(self, mock_get, mock_whois_response):
        """Test domain age validation logic"""
        # Test new domain (suspicious)
        mock_get.return_value = mock_whois_response(creation_date="2023-12-01T00:00:00Z")
        
        result = check_domain_reputation("new-suspicious-domain.com")
        assert result["suspicious"], "New domain should be flagged as suspicious"
        assert "recent registration" in result["reasons"][0].lower()
        
        # Test established domain (legitimate)
        mock_get.return_value = mock_whois_response(creation_date="2010-01-01T00:00:00Z")
        
        result = check_domain_reputation("established-domain.com")
        assert not result["suspicious"], "Established domain should not be flagged"
    
    @patch("requests.get")
    def test_suspicious_registrar_detection(self, mock_get, mock_whois_response):
        """Test detection of suspicious domain registrars"""
        # Test suspicious registrar
        mock_get.return_value = mock_whois_response(registrar="Anonymous Domains Ltd")
        
        result = check_domain_reputation("suspicious-registrar.com")
        assert result["suspicious"], "Domain with suspicious registrar should be flagged"
        
        # Test legitimate registrar
        mock_get.return_value = mock_whois_response(registrar="GoDaddy.com, LLC")
        
        result = check_domain_reputation("legitimate-registrar.com")
        assert not result["suspicious"], "Domain with legitimate registrar should not be flagged"
    
    @patch("requests.get")
    def test_api_error_handling(self, mock_get, mock_whois_response):
        """Test handling of API errors"""
        mock_get.return_value = mock_whois_response(is_error=True)
        
        result = check_domain_reputation("error-test.com")
        assert "error" in result, "API errors should be handled gracefully"


# Tests for URL Component Analysis
class TestURLComponentAnalysis:
    
    def test_url_component_extraction(self, url_components):
        """Test extraction of URL components"""
        for url, expected in url_components.items():
            components = extract_url_components(url)
            
            # Check main components
            assert components["scheme"] == expected["scheme"]
            assert components["netloc"] == expected["netloc"]
            assert components["path"] == expected["path"]
            assert components["query"] == expected["query"]
            
            # Check derived components
            assert components["domain"] == expected["domain"]
            assert components["tld"] == expected["tld"]
            
            if "subdomain" in expected:
                assert components["subdomain"] == expected["subdomain"]
    
    def test_detect_deceptive_domains(self):
        """Test detection of deceptive domains (typosquatting, etc.)"""
        deceptive_domains = [
            "paypa1.com",         # Number instead of letter
            "g00gle.com",         # Multiple number substitutions
            "arnazon.com",        # Similar looking letters
            "mircosoft.com",      # Transposed letters
            "faceb00k-login.com"  # Number substitution with additions
        ]
        
        for domain in deceptive_domains:
            url = f"https://www.{domain}/login"
            components = extract_url_components(url)
            patterns = detect_suspicious_patterns(url)
            
            assert len(patterns) > 0, f"Failed to detect deceptive domain: {domain}"
    
    def test_excessive_subdomains(self):
        """Test detection of excessive subdomains"""
        url = "https://login.secure.verify.account.example.com/signin"
        components = extract_url_components(url)
        
        patterns = detect_suspicious_patterns(url)
        assert any("subdomain" in pattern.lower() for pattern in patterns), "Failed to detect excessive subdomains"


# Tests for Suspicious Redirect Detection
class TestRedirectDetection:
    
    @patch("requests.get")
    def test_redirect_chain_detection(self, mock_get):
        """Test detection of redirect chains"""
        # Mock a chain of redirects
        responses = [
            MagicMock(status_code=301, headers={"Location": "http://second-url.com/path"}),
            MagicMock(status_code=302, headers={"Location": "http://third-url.com/path"}),
            MagicMock(status_code=200, headers={})
        ]
        
        mock_get.side_effect = responses
        
        result = check_redirects("http://initial-url.com/path")
        
        assert result["redirect_count"] == 2
        assert len(result["redirect_chain"]) == 2
        assert result["final_url"] == "http://third-url.com/path"
        assert result["suspicious"]
    
    @patch("requests.get")
    def test_cross_domain_redirect_detection(self, mock_get):
        """Test detection of cross-domain redirects"""
        # Mock a redirect to a different domain
        mock_get.return_value = MagicMock(
            status_code=302,
            headers={"Location": "https://different-domain.com/path"},
            history=[
                MagicMock(
                    status_code=301,
                    headers={"Location": "https://different-domain.com/path"},
                    url="https://original-domain.com/path"
                )
            ]
        )
        
        result = check_redirects("https://original-domain.com/path")
        
        assert result["redirect_count"] == 1
        assert result["domain_changes"] == 1
        assert result["suspicious"]
    
    @patch("requests.get")
    def test_safe_redirect_within_domain(self, mock_get):
        """Test safe redirects within the same domain"""
        # Mock a redirect within the same domain
        mock_get.return_value = MagicMock(
            status_code=200,
            history=[
                MagicMock(
                    status_code=301,
                    headers={"Location": "https://example.com/new-path"},
                    url="https://example.com/old-path"
                )
            ]
        )
        
        result = check_redirects("https://example.com/old-path")
        
        assert result["redirect_count"] == 1
        assert result["domain_changes"] == 0
        assert not result["suspicious"]
    
    @patch("requests.get")
    def test_exception_handling(self, mock_get):
        """Test handling of exceptions during redirect checking"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = check_redirects("https://error-site.com")
        
        assert "error" in result
        assert "Connection error" in result["error"]


# Tests for URL Scoring System
class TestURLScoring:
    
    def test_scoring_system_phishing_urls(self, phishing_urls):
        """Test that phishing URLs receive high scores"""
        for url in phishing_urls:
            score_result = calculate_url_score(url)
            
            assert score_result["score"] > 0.7, f"Phishing URL should have high score: {url}"
            assert len(score_result["factors"]) > 0
    
    def test_scoring_system_legitimate_urls(self, legitimate_urls):
        """Test that legitimate URLs receive low scores"""
        for url in legitimate_urls:
            score_result = calculate_url_score(url)
            
            assert score_result["score"] < 0.3, f"Legitimate URL should have low score: {url}"
            assert len(score_result["factors"]) == 0 or all(factor["type"] == "safe" for factor in score_result["factors"])
    
    def test_scoring_mixed_indicators(self):
        """Test URLs with mixed safety indicators"""
        mixed_urls = [
            # HTTPS but suspicious domain
            "https://paypal-account-verify.com/login",
            # Legitimate domain but unusual path
            "https://www.amazon.com/signin/verify_identity?suspicious=true&redirect=http://external.com",
            # Unusual TLD but otherwise normal
            "https://microsoft.tk/account"
        ]
        
        for url in mixed_urls:
            score_result = calculate_url_score(url)
            
            # Mixed indicator URLs should have moderate scores
            assert 0.3 <= score_result["score"] <= 0.7, f"Mixed indicator URL should have moderate score: {url}"
            
            # Should contain both positive and negative factors
            has_positive = any(factor["impact"] > 0 for factor in score_result["factors"])
            has_negative = any(factor["impact"] < 0 for factor in score_result["factors"])
            
            assert has_positive and has_negative, f"Should have both positive and negative factors: {url}"
    
    def test_scoring_weights(self):
        """Test that scoring weights are appropriate"""
        # Test that critical indicators have high impact
        high_impact_url = "http://paypal.com.secure.malicious-domain.ru/verify"
        high_result = calculate_url_score(high_impact_url)
        
        # Test that minor indicators have lower impact
        low_impact_url = "https://www.amazon.com/signin?session=expired"
        low_result = calculate_url_score(low_impact_url)
        
        # Critical indicators should have more impact
        assert high_result["score"] > 0.7
        assert low_result["score"] < 0.3
        
        # Check specific factor weights
        critical_factors = [f for f in high_result["factors"] if f["impact"] > 0.3]
        assert len(critical_factors) > 0, "Should identify critical factors with high impact"


# Tests for TLD Analysis
class TestTLDAnalysis:
    
    def test_suspicious_tlds(self):
        """Test detection of suspicious TLDs"""
        suspicious_tld_urls = [
            "http://login-verify.tk/account",  # Tokelau - often abused
            "https://secure-bank.ml/login",    # Mali - often abused
            "http://account-verify.ga/signin", # Gabon - often abused
            "https://paypal-secure.gq/verify", # Equatorial Guinea - often abused
            "http://microsoft-account.cf/auth"  # Central African Republic - often abused
        ]
        
        for url in suspicious_tld_urls:
            tld_result = analyze_tld(url)
            
            assert tld_result["suspicious"], f"Should flag suspicious TLD in: {url}"
            assert "high-risk TLD" in tld_result["reason"].lower() or "commonly abused" in tld_result["reason"].lower()
    
    def test_legitimate_tlds(self):
        """Test recognition of legitimate TLDs"""
        legitimate_tld_urls = [
            "https://example.com/login",       # .com - common legitimate
            "https://university.edu/portal",   # .edu - restricted educational
            "https://government.gov/services", # .gov - restricted government
            "https://organization.org/about",  # .org - common legitimate
            "https://business.co.uk/contact"   # country code - typically legitimate
        ]
        
        for url in legitimate_tld_urls:
            tld_result = analyze_tld(url)
            
            assert not tld_result["suspicious"], f"Should not flag legitimate TLD in: {url}"
    
    def test_rare_but_legitimate_tlds(self):
        """Test handling of rare but legitimate TLDs"""
        rare_tld_urls = [
            "https://website.museum/exhibit",   # .museum - restricted but rare
            "https://domain.travel/booking",    # .travel - industry specific
            "https://company.jobs/careers",     # .jobs - industry specific
            "https://service.int/portal"        # .int - international organizations
        ]
        
        for url in rare_tld_urls:
            tld_result = analyze_tld(url)
            
            # Might have higher scrutiny but shouldn't be automatically suspicious
            assert tld_result.get("rare", False), f"Should identify rare TLD in: {url}"
            assert not tld_result["suspicious"], f"Should not flag rare but legitimate TLD as suspicious: {url}"
    
    def test_country_code_tlds(self):
        """Test analysis of country code TLDs"""
        country_tlds = [
            ("https://website.ru/page", True),    # Russia - higher scrutiny
            ("https://company.cn/product", True), # China - higher scrutiny
            ("https://service.ir/login", True),   # Iran - higher scrutiny
            ("https://example.de/contact", False),  # Germany - lower risk
            ("https://domain.ca/about", False)      # Canada - lower risk
        ]
        
        for url, expected_higher_scrutiny in country_tlds:
            tld_result = analyze_tld(url)
            
            if expected_higher_scrutiny:
                assert tld_result.get("higher_scrutiny", False), f"Should flag higher scrutiny for: {url}"
            else:
                assert not tld_result.get("higher_scrutiny", False), f"Should not flag higher scrutiny for: {url}"
    
    def test_new_gtlds(self):
        """Test handling of new generic TLDs"""
        new_gtlds = [
            "https://company.tech/products",
            "https://blog.app/articles",
            "https://store.shop/products",
            "https://personal.site/portfolio"
        ]
        
        for url in new_gtlds:
            tld_result = analyze_tld(url)
            
            # New gTLDs should be identified but not automatically suspicious
            assert tld_result.get("new_gtld", False), f"Should identify new gTLD in: {url}"
            assert not tld_result["suspicious"], f"Should not flag new gTLD as automatically suspicious: {url}"


# Integration Tests for Full URL Analysis
class TestFullURLAnalysis:
    
    @patch("utils.url_analyzer.check_domain_reputation")
    @patch("utils.url_analyzer.check_redirects")
    def test_full_analysis_phishing_url(self, mock_redirects, mock_reputation):
        """Test full analysis pipeline with a phishing URL"""
        # Mock dependencies
        mock_reputation.return_value = {
            "suspicious": True,
            "reasons": ["Recently registered domain"]
        }
        
        mock_redirects.return_value = {
            "redirect_count": 2,
            "domain_changes": 1,
            "suspicious": True,
            "redirect_chain": ["http://initial.com", "http://intermediate.com", "http://final.com"],
            "final_url": "http://final.com"
        }
        
        phishing_url = "http://paypal-secure.signin.com-id.me/verification"
        result = analyze_url(phishing_url)
        
        # Check results
        assert result.is_suspicious
        assert result.score > 0.7
        assert len(result.suspicious_elements) >= 3
        assert any("TLD" in element for element in result.suspicious_elements)
        assert any("domain" in element for element in result.suspicious_elements)
        assert any("pattern" in element for element in result.suspicious_elements)
    
    @patch("utils.url_analyzer.check_domain_reputation")
    @patch("utils.url_analyzer.check_redirects")
    def test_full_analysis_legitimate_url(self, mock_redirects, mock_reputation):
        """Test full analysis pipeline with a legitimate URL"""
        # Mock dependencies
        mock_reputation.return_value = {
            "suspicious": False,
            "reasons": []
        }
        
        mock_redirects.return_value = {
            "redirect_count": 0,
            "domain_changes": 0,
            "suspicious": False,
            "redirect_chain": [],
            "final_url": "https://www.paypal.com/signin"
        }
        
        legitimate_url = "https://www.paypal.com/signin"
        result = analyze_url(legitimate_url)
        
        # Check results
        assert not result.is_suspicious
        assert result.score < 0.3
        assert len(result.suspicious_elements) == 0
        assert len(result.safe_elements) >= 2
    
    def test_analysis_with_null_input(self):
        """Test handling of null or invalid inputs"""
        with pytest.raises(ValueError):
            analyze_url(None)
        
        with pytest.raises(ValueError):
            analyze_url("")
    
    def test_malformed_url_handling(self):
        """Test handling of malformed URLs"""
        malformed_urls = [
            "not-a-url",
            "http:/missing-slash.com",
            "https://no-tld",
            "hxxp://suspicious-format.com"
        ]
        
        for url in malformed_urls:
            result = analyze_url(url)
            
            # Should identify as suspicious due to malformation
            assert result.is_suspicious
            assert "malformed" in str(result.suspicious_elements).lower()
    
    @patch("utils.url_analyzer.requests.get")
    def test_exception_handling_in_full_pipeline(self, mock_get):
        """Test that exceptions in the pipeline are handled gracefully"""
        # Simulate a request exception
        mock_get.side_effect = requests.exceptions.RequestException("Test exception")
        
        url = "https://example.com/test"
        result = analyze_url(url)
        
        # Should still return a result despite the exception
        assert result is not None
        assert hasattr(result, 'score')
        assert hasattr(result, 'is_suspicious')
        
        # Error should be noted in the result
        assert any("error" in str(element).lower() for element in result.suspicious_elements)


if __name__ == "__main__":
    pytest.main(["-v", __file__])
