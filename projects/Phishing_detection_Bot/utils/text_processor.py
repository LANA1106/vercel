"""
Text processing module for phishing detection.

This module provides functions to analyze text content for phishing indicators,
including urgency language, threats, credential requests, and other common 
patterns found in phishing attempts.
"""

import re
import logging
import json
from typing import Dict, List, Optional, Any, Tuple, NamedTuple
from dataclasses import dataclass, field
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure required NLTK data is available
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    logger.info("Downloading required NLTK data...")
    nltk.download('punkt')
    nltk.download('stopwords')

# Constants for pattern detection
COMMON_PATTERNS = {
    "urgency": r"\b(urgent|immediate|immediately|quickly|expires|limited time|today|now|soon|act now)\b",
    "threat": r"\b(suspend|disable|terminate|block|restrict|limit|cancel|close|delete|locked)\b",
    "credentials": r"\b(password|username|login|sign in|verify|confirm|authenticate|credential|authorization)\b",
    "personal_info": r"\b(ssn|social security|credit card|bank account|address|birthday|dob|payment|billing)\b",
    "action_request": r"\b(click|tap|follow|open|download|update|upgrade|install|activate|validate)\b",
    "security": r"\b(security|secure|protected|safe|trusted|verified|encryption|authentication)\b",
    "reward": r"\b(free|bonus|prize|gift|reward|won|winner|exclusive|limited offer|discount)\b",
    "urgency_punctuation": r"[!]{2,}|[?!]{2,}",
    "unusual_sender": r"\b(support|service|admin|help|team|update|security|account|billing|payment|info)[@.]\b",
    "suspicious_greeting": r"\b(dear customer|valued customer|account holder|user|client|member)\b"
}

# Banks and financial services often targeted in phishing
FINANCIAL_ENTITIES = [
    "bank", "paypal", "visa", "mastercard", "american express", "amex", 
    "chase", "wells fargo", "citibank", "bank of america", "capital one",
    "discover", "td bank", "pnc", "hsbc", "barclays", "santander", "stripe",
    "venmo", "zelle", "cash app", "western union", "moneygram", "cryptocurrency",
    "bitcoin", "ach", "wire transfer", "direct deposit", "tax", "irs"
]

# Tech companies often impersonated in phishing attacks
TECH_COMPANIES = [
    "microsoft", "apple", "google", "facebook", "amazon", "netflix", "instagram",
    "twitter", "linkedin", "dropbox", "icloud", "gmail", "outlook", "office365",
    "onedrive", "xbox", "playstation", "steam", "adobe", "zoom", "teams"
]

# Banks and payment services have higher phishing risk
COMPANY_WEIGHTS = {
    "bank": 0.35,
    "paypal": 0.35, 
    "payment": 0.3,
    "account": 0.25,
    "amazon": 0.25,
    "apple": 0.25,
    "microsoft": 0.25,
    "google": 0.20,
    "facebook": 0.20,
    "netflix": 0.20
}

# Pattern weights for scoring
PATTERN_WEIGHTS = {
    "urgency": 0.25,
    "threat": 0.3,
    "credentials": 0.3,
    "personal_info": 0.35,
    "action_request": 0.2,
    "security": 0.15,
    "reward": 0.15,
    "urgency_punctuation": 0.1,
    "unusual_sender": 0.25,
    "suspicious_greeting": 0.15
}

# Results returned by analysis functions
@dataclass
class TextAnalysisResult:
    """Result of text analysis for phishing detection."""
    score: float = 0.0
    detected_patterns: List[Dict[str, Any]] = field(default_factory=list)
    is_phishing: bool = False
    confidence: float = 0.0
    context_score: float = 0.0
    
    def __post_init__(self):
        """Calculate derived fields after initialization."""
        self.confidence = min(self.score * 1.5, 1.0)


def load_custom_rules(config_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Load custom detection rules from configuration file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        List of custom rule dictionaries
    """
    default_path = os.path.join("config", "phishing_data.json")
    config_path = config_file or default_path
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as file:
                config = json.load(file)
                return config.get("custom_rules", [])
        else:
            logger.warning(f"Config file not found: {config_path}")
            return []
    except (json.JSONDecodeError, PermissionError) as e:
        logger.error(f"Error loading config file: {e}")
        return []


def preprocess_text(text: str) -> str:
    """
    Preprocess text for analysis by converting to lowercase and removing extra whitespace.
    
    Args:
        text: The text to preprocess
        
    Returns:
        Preprocessed text
    """
    if not text:
        return ""
        
    # Convert to lowercase
    text = text.lower()
    
    # Replace multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove leading/trailing whitespace
    text = text.strip()
    
    return text


def extract_patterns(text: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract suspicious patterns from the given text.
    
    Args:
        text: The text to analyze
        config_file: Optional path to a configuration file
        
    Returns:
        List of detected patterns with metadata
    """
    if not text:
        return []
        
    # Preprocess the text
    processed_text = preprocess_text(text)
    
    # Load custom rules if specified
    custom_rules = load_custom_rules(config_file)
    
    # Find patterns in the text
    detected_patterns = []
    
    # Check for common patterns
    for pattern_type, regex in COMMON_PATTERNS.items():
        matches = re.finditer(regex, processed_text, re.IGNORECASE)
        for match in matches:
            detected_patterns.append({
                "type": pattern_type,
                "pattern": match.group(0),
                "position": (match.start(), match.end()),
                "weight": PATTERN_WEIGHTS.get(pattern_type, 0.1)
            })
    
    # Check for custom rules
    for rule in custom_rules:
        try:
            pattern = rule.get("pattern", "")
            weight = rule.get("weight", 0.5)
            description = rule.get("description", "Custom rule")
            
            matches = re.finditer(pattern, processed_text, re.IGNORECASE)
            for match in matches:
                detected_patterns.append({
                    "type": "custom",
                    "pattern": match.group(0),
                    "position": (match.start(), match.end()),
                    "weight": weight,
                    "description": description
                })
        except re.error as e:
            logger.error(f"Invalid regex pattern in custom rule: {e}")
    
    # Check for financial entities
    for entity in FINANCIAL_ENTITIES:
        if entity in processed_text:
            detected_patterns.append({
                "type": "financial_entity",
                "pattern": entity,
                "position": (processed_text.find(entity), processed_text.find(entity) + len(entity)),
                "weight": COMPANY_WEIGHTS.get(entity, 0.25)
            })
    
    # Check for tech company names
    for company in TECH_COMPANIES:
        if company in processed_text:
            detected_patterns.append({
                "type": "tech_company",
                "pattern": company,
                "position": (processed_text.find(company), processed_text.find(company) + len(company)),
                "weight": COMPANY_WEIGHTS.get(company, 0.2)
            })
    
    return detected_patterns


def calculate_context_score(text: str) -> float:
    """
    Calculate a context score based on the presence of certain keywords or combinations.
    
    Args:
        text: The text to analyze
        
    Returns:
        A context score between 0 and 1
    """
    processed_text = preprocess_text(text)
    context_score = 0.0
    
    # Check for banking context
    if any(keyword in processed_text for keyword in ["bank", "account", "credit", "debit", "transaction"]):
        context_score += 0.2
    
    # Check for urgent financial context
    if any(urg in processed_text for urg in ["urgent", "immediate"]) and \
       any(fin in processed_text for fin in ["payment", "transaction", "transfer", "money"]):
        context_score += 0.3
    
    # Check for security alert context
    if any(sec in processed_text for sec in ["security", "alert", "warning"]) and \
       any(acc in processed_text for acc in ["account", "password", "login"]):
        context_score += 0.25
    
    # Check for request for personal information
    if any(req in processed_text for req in ["provide", "update", "confirm"]) and \
       any(info in processed_text for info in ["information", "details", "card", "ssn", "identity"]):
        context_score += 0.35
    
    # Cap at 1.0
    return min(context_score, 1.0)


def analyze_text(text: str, config_file: Optional[str] = None) -> TextAnalysisResult:
    """
    Analyze text for phishing indicators.
    
    Args:
        text: The text to analyze
        config_file: Optional path to a configuration file
        
    Returns:
        TextAnalysisResult with analysis details
    """
    if text is None:
        raise ValueError("Text cannot be None")
    
    if not text:
        return TextAnalysisResult(score=0.0, detected_patterns=[])
    
    # Extract patterns from the text
    patterns = extract_patterns(text, config_file)
    
    if not patterns:
        return TextAnalysisResult(score=0.0, detected_patterns=[])
    
    # Calculate scores
    pattern_score = sum(pattern["weight"] for pattern in patterns) / max(1.0, len(patterns) / 2)
    context_score = calculate_context_score(text)
    
    # Combine scores (weighted average)
    combined_score = (pattern_score * 0.7) + (context_score * 0.3)
    
    # Normalize to 0-1 range
    normalized_score = min(combined_score, 1.0)
    
    # Create and return results
    return TextAnalysisResult(
        score=normalized_score,
        detected_patterns=patterns,
        is_phishing=normalized_score > 0.6,  # Default threshold
        context_score=context_score
    )


class MessageCheckResult:
    """Result of a full message check including URL and text analysis."""
    
    def __init__(self, text_score: float = 0.0, url_score: float = 0.0, 
                 combined_score: float = 0.0, is_phishing: bool = False,
                 detected_patterns: List[Dict[str, Any]] = None,
                 suspicious_urls: List[str] = None):
        self.text_score = text_score
        self.url_score = url_score
        self.combined_score = combined_score
        self.is_phishing = is_phishing
        self.detected_patterns = detected_patterns or []
        self.suspicious_urls = suspicious_urls or []


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text that may contain URLs
        
    Returns:
        List of extracted URLs
    """
    # URL regex pattern
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    # Extract URLs
    return re.findall(url_pattern, text)


if __name__ == "__main__":
    # Example usage
    sample_text = "URGENT: Your account has been compromised. Please verify your identity immediately by clicking on http://suspicious-site.com/login"
    result = analyze_text(sample_text)
    
    print(f"Phishing score: {result.score:.2f}")
    print(f"Is phishing: {result.is_phishing}")
    print("Detected patterns:")
    for pattern in result.detected_patterns:
        print(f"- {pattern['type']}: {pattern['pattern']} (weight: {pattern['weight']})")

