import pytest
import json
import os
import sys
from unittest.mock import MagicMock, patch

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.text_processor import analyze_text, extract_patterns
from phishguard import PhishGuard, PhishingDetector


# Fixtures for test data
@pytest.fixture
def mock_config():
    """Provides mock configuration data for testing"""
    return {
        "detection": {
            "url_threshold": 0.7,
            "text_threshold": 0.6,
            "combined_threshold": 0.65
        },
        "custom_rules": [
            {
                "pattern": r"\b(urgent|immediately)\b.*\b(password|account|suspend)\b",
                "weight": 0.8,
                "description": "Urgent action password/account rule"
            },
            {
                "pattern": r"\b(verify|confirm)\b.*\b(identity|account)\b",
                "weight": 0.6,
                "description": "Verification request rule"
            }
        ],
        "common_patterns": {
            "urgency": r"\b(urgent|immediate|quickly|expires|limited time)\b",
            "threat": r"\b(suspend|disable|terminate|block|restrict|limit)\b",
            "credentials": r"\b(password|username|login|sign in|verify|confirm)\b",
            "personal_info": r"\b(ssn|social security|credit card|bank account|address|birthday|dob)\b"
        }
    }


@pytest.fixture
def mock_phishing_messages():
    """Provides sample phishing messages for testing"""
    return [
        "URGENT: Your account will be suspended! Verify your password immediately at secure-bank.com-verify.net",
        "Your PayPal account has been limited. Please click the link to confirm your identity: paypal-secure.verifyid45.com",
        "Amazon: There is a problem with your payment method. Update your credit card details within 24 hours: amazonn-secure.com/signin",
        "Dear customer, we detected suspicious activity. Verify your account immediately to prevent suspension: bankofamerica.authorize.domain.co"
    ]


@pytest.fixture
def mock_legitimate_messages():
    """Provides sample legitimate messages for testing"""
    return [
        "Thank you for your recent purchase. Your order #12345 has been shipped.",
        "Your monthly statement is now available in your online banking portal.",
        "We've updated our privacy policy. No action is required.",
        "Join us for our upcoming webinar on cybersecurity practices."
    ]


@pytest.fixture
def mock_detector(mock_config):
    """Creates a PhishingDetector instance with mock configuration"""
    detector = PhishingDetector()
    detector.config = mock_config
    return detector


# Text Analysis Tests
class TestTextAnalysis:
    
    def test_analyze_text_phishing_content(self, mock_detector, mock_phishing_messages):
        """Test that phishing content is correctly identified"""
        for message in mock_phishing_messages:
            result = mock_detector.analyze_text(message)
            assert result.score > mock_detector.config["detection"]["text_threshold"]
            assert len(result.detected_patterns) > 0
    
    def test_analyze_text_legitimate_content(self, mock_detector, mock_legitimate_messages):
        """Test that legitimate content is correctly identified"""
        for message in mock_legitimate_messages:
            result = mock_detector.analyze_text(message)
            assert result.score < mock_detector.config["detection"]["text_threshold"]
    
    def test_analyze_text_empty_content(self, mock_detector):
        """Test behavior with empty text"""
        result = mock_detector.analyze_text("")
        assert result.score == 0
        assert len(result.detected_patterns) == 0
    
    def test_analyze_text_null_input(self, mock_detector):
        """Test behavior with None input"""
        with pytest.raises(ValueError):
            mock_detector.analyze_text(None)


# Pattern Matching Tests
class TestPatternMatching:
    
    def test_common_phishing_patterns(self, mock_detector):
        """Test detection of common phishing patterns"""
        text = "Please verify your account details urgently to avoid suspension"
        patterns = mock_detector.extract_patterns(text)
        
        assert any("urgency" in pattern for pattern in patterns)
        assert any("threat" in pattern for pattern in patterns)
        assert any("credentials" in pattern for pattern in patterns)
    
    def test_custom_rules_matching(self, mock_detector):
        """Test matching against custom rules"""
        text = "You need to verify your identity immediately"
        patterns = mock_detector.extract_patterns(text)
        
        assert len(patterns) > 0
        assert any("Verification request rule" in pattern.get("description", "") for pattern in patterns)
    
    def test_pattern_weights_calculation(self, mock_detector):
        """Test that pattern weights are correctly calculated"""
        text = "URGENT: Verify your password immediately to prevent account suspension"
        result = mock_detector.analyze_text(text)
        
        # This text should match multiple patterns including high-weight ones
        assert result.score > 0.7
    
    def test_no_pattern_match(self, mock_detector):
        """Test behavior when no patterns match"""
        text = "The weather is nice today"
        result = mock_detector.analyze_text(text)
        
        assert result.score == 0
        assert len(result.detected_patterns) == 0


# Threshold Testing
class TestThresholds:
    
    def test_borderline_threshold_cases(self, mock_detector):
        """Test behavior near threshold boundaries"""
        # Create a message that should score near the threshold
        borderline_message = "Please update your account information soon"
        
        # Test with different thresholds
        original_threshold = mock_detector.config["detection"]["text_threshold"]
        
        # Set threshold just above the expected score
        mock_detector.config["detection"]["text_threshold"] = 0.4
        result1 = mock_detector.check_message(borderline_message)
        
        # Set threshold just below the expected score
        mock_detector.config["detection"]["text_threshold"] = 0.2
        result2 = mock_detector.check_message(borderline_message)
        
        # Restore original threshold
        mock_detector.config["detection"]["text_threshold"] = original_threshold
        
        # The results should differ based on threshold
        assert result1.is_phishing != result2.is_phishing
    
    def test_combined_threshold_logic(self, mock_detector):
        """Test the combined threshold logic with URL and text analysis"""
        with patch('utils.url_analyzer.analyze_url') as mock_url_analyze:
            # Mock URL analysis to return a moderate score
            mock_url_analyze.return_value = MagicMock(score=0.6, suspicious_elements=["unusual_domain"])
            
            message = "Click here to update: http://suspicious-url.com"
            
            # With default thresholds
            result = mock_detector.check_message(message)
            
            # The combined score should use both text and URL analysis
            assert result.combined_score > 0
            assert result.combined_score == pytest.approx((result.text_score + 0.6) / 2, 0.01)


# Message Context Analysis
class TestMessageContextAnalysis:
    
    def test_url_extraction_from_message(self, mock_detector):
        """Test extraction of URLs from message content"""
        message = "Check this link: http://example.com and also https://phishing-site.com/verify"
        
        with patch('utils.url_analyzer.analyze_url') as mock_url_analyze:
            mock_url_analyze.return_value = MagicMock(score=0.8, suspicious_elements=["suspicious_domain"])
            
            result = mock_detector.check_message(message)
            
            # Should find both URLs
            assert mock_url_analyze.call_count == 2
    
    def test_message_with_no_urls(self, mock_detector):
        """Test behavior when message contains no URLs"""
        message = "This is a simple message with no URLs"
        
        with patch('utils.url_analyzer.analyze_url') as mock_url_analyze:
            result = mock_detector.check_message(message)
            
            # Should not call URL analyzer
            mock_url_analyze.assert_not_called()
            
            # Result should only have text analysis
            assert result.url_score == 0
            assert result.combined_score == result.text_score
    
    def test_context_sensitive_analysis(self, mock_detector):
        """Test that detection is sensitive to message context"""
        # A message about banking should be more suspicious when containing certain patterns
        banking_context = "Your bank account requires verification"
        normal_context = "Your subscription requires verification"
        
        banking_result = mock_detector.analyze_text(banking_context)
        normal_result = mock_detector.analyze_text(normal_context)
        
        # Banking context should score higher for phishing
        assert banking_result.score > normal_result.score


# Integration Tests with Mock Data
class TestIntegration:
    
    @patch('json.load')
    def test_detector_with_config_file(self, mock_json_load, mock_config):
        """Test detector initialization with config file"""
        mock_json_load.return_value = mock_config
        
        with patch('builtins.open', MagicMock()):
            detector = PhishingDetector()
            detector.load_config("config/phishing_data.json")
            
            assert detector.config == mock_config
    
    @patch('utils.url_analyzer.analyze_url')
    @patch('utils.text_processor.analyze_text')
    def test_full_message_check_integration(self, mock_text_analyze, mock_url_analyze, mock_detector):
        """Test full integration of message checking"""
        # Mock the components
        mock_text_analyze.return_value = MagicMock(
            score=0.75, 
            detected_patterns=[{"type": "urgency", "weight": 0.8}]
        )
        mock_url_analyze.return_value = MagicMock(
            score=0.85, 
            suspicious_elements=["suspicious_domain", "unusual_path"]
        )
        
        message = "URGENT: Verify your account now: http://bank-secure.suspicious-domain.com"
        
        # Function under test
        with patch.object(mock_detector, 'analyze_text', mock_text_analyze):
            with patch.object(mock_detector, 'analyze_url', mock_url_analyze):
                result = mock_detector.check_message(message)
        
        # Verify the result combines both analyses
        assert result.is_phishing is True
        assert result.text_score > mock_detector.config["detection"]["text_threshold"]
        assert result.url_score > mock_detector.config["detection"]["url_threshold"]
        assert result.combined_score > mock_detector.config["detection"]["combined_threshold"]
    
    def test_real_world_examples(self, mock_detector, mock_phishing_messages, mock_legitimate_messages):
        """Test with a variety of real-world messages"""
        # Test all phishing messages
        for message in mock_phishing_messages:
            result = mock_detector.check_message(message)
            assert result.is_phishing is True, f"Failed to detect phishing: {message}"
        
        # Test all legitimate messages
        for message in mock_legitimate_messages:
            result = mock_detector.check_message(message)
            assert result.is_phishing is False, f"False positive: {message}"


if __name__ == "__main__":
    pytest.main(["-v", __file__])

