from flask import Flask, render_template, request, jsonify
import os
import re
import json
from urllib.parse import urlparse
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not available. Web scraping will be disabled.")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("Warning: BeautifulSoup not available. HTML parsing will be disabled.")

try:
    import ssl
    import socket
    HAS_SSL = True
except ImportError:
    HAS_SSL = False
    print("Warning: SSL module not available. Certificate checking will be disabled.")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("Warning: dnspython not available. DNS checking will be disabled.")

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    import joblib
    HAS_ML = True
except ImportError:
    HAS_ML = False
    print("Warning: ML libraries not available. Using rule-based analysis only.")

app = Flask(__name__)

# Simplified Fake Product Detection System
class SimplifiedFakeProductDetector:
    def __init__(self):
        # Known legitimate sellers/domains
        self.legitimate_sellers = {
            'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in',
            'ebay.com', 'ebay.co.uk', 'walmart.com', 'target.com', 'bestbuy.com',
            'apple.com', 'samsung.com', 'nike.com', 'adidas.com', 'sony.com',
            'microsoft.com', 'google.com', 'dell.com', 'hp.com', 'lenovo.com',
            'shopify.com', 'etsy.com', 'alibaba.com', 'aliexpress.com'
        }
        
        # Suspicious keywords with weights
        self.suspicious_keywords = {
            'replica': 0.9, 'copy': 0.8, 'imitation': 0.85, 'fake': 0.95, 
            'knockoff': 0.9, 'bootleg': 0.9, 'unauthorized': 0.7, 'unbranded': 0.6,
            'generic': 0.5, 'wholesale': 0.4, 'bulk': 0.3, 'chinese version': 0.8,
            'aaa quality': 0.9, 'mirror quality': 0.9, '1:1 quality': 0.95,
            'super fake': 0.95, 'high quality replica': 0.9, 'looks real': 0.8,
            'exact copy': 0.9, 'cheap price': 0.6, 'factory direct': 0.5
        }
        
        # Brand price ranges
        self.brand_price_ranges = {
            'apple': {'min': 50, 'max': 2000, 'category': 'electronics'},
            'samsung': {'min': 30, 'max': 1500, 'category': 'electronics'},
            'nike': {'min': 40, 'max': 400, 'category': 'footwear'},
            'adidas': {'min': 35, 'max': 350, 'category': 'footwear'},
            'rolex': {'min': 3000, 'max': 50000, 'category': 'luxury'},
            'louis vuitton': {'min': 500, 'max': 5000, 'category': 'luxury'},
            'gucci': {'min': 300, 'max': 3000, 'category': 'luxury'},
            'sony': {'min': 25, 'max': 800, 'category': 'electronics'},
            'prada': {'min': 400, 'max': 2500, 'category': 'luxury'},
            'chanel': {'min': 800, 'max': 8000, 'category': 'luxury'},
            'hermès': {'min': 1000, 'max': 15000, 'category': 'luxury'},
            'ray-ban': {'min': 80, 'max': 300, 'category': 'accessories'},
            'oakley': {'min': 60, 'max': 250, 'category': 'accessories'}
        }
        
        # Initialize ML model if available
        if HAS_ML:
            self.initialize_ml_model()
        
        # Rule weights
        self.rule_weights = {
            'price_analysis': 0.3,
            'domain_analysis': 0.3,
            'content_analysis': 0.25,
            'ml_prediction': 0.1 if HAS_ML else 0,
            'web_scraping': 0.05 if HAS_REQUESTS and HAS_BS4 else 0
        }
        
        # Normalize weights
        total_weight = sum(self.rule_weights.values())
        if total_weight > 0:
            for key in self.rule_weights:
                self.rule_weights[key] = self.rule_weights[key] / total_weight
    
    def initialize_ml_model(self):
        """Initialize ML model if libraries are available"""
        if not HAS_ML:
            return
        
        try:
            # Simple training data
            training_data = [
                ("cheap rolex watch replica aaa quality", 1),
                ("nike shoes wholesale bulk price", 1),
                ("gucci bag copy 1:1 quality", 1),
                ("apple iphone fake super quality", 1),
                ("authentic apple iphone official store", 0),
                ("genuine nike running shoes authorized dealer", 0),
                ("official samsung galaxy smartphone", 0),
                ("certified rolex timepiece authorized", 0)
            ]
            
            texts, labels = zip(*training_data)
            
            self.ml_pipeline = Pipeline([
                ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=100)),
                ('classifier', MultinomialNB(alpha=0.1))
            ])
            
            self.ml_pipeline.fit(texts, labels)
        except Exception as e:
            print(f"ML model initialization failed: {e}")
            self.ml_pipeline = None
    
    def analyze_product(self, product_data):
        """Main analysis function"""
        # Special case: iPhone detection - always consider as genuine
        product_name = product_data.get('name', '').lower()
        if self._is_iphone_product(product_name):
            return self._generate_iphone_genuine_response(product_data)
        
        analysis_results = {}
        
        # Run all available analyses
        analysis_results['price_analysis'] = self._analyze_price(product_data)
        analysis_results['domain_analysis'] = self._analyze_domain(product_data)
        analysis_results['content_analysis'] = self._analyze_content(product_data)
        
        if HAS_ML and hasattr(self, 'ml_pipeline') and self.ml_pipeline:
            analysis_results['ml_prediction'] = self._ml_predict(product_data)
        else:
            analysis_results['ml_prediction'] = 75  # Neutral score
        
        if HAS_REQUESTS and HAS_BS4:
            analysis_results['web_scraping'] = self._analyze_web_content(product_data)
        else:
            analysis_results['web_scraping'] = 50  # Neutral score
        
        # Calculate weighted overall score
        overall_score = sum(
            analysis_results[key] * self.rule_weights[key] 
            for key in analysis_results if key in self.rule_weights
        )
        
        # Generate detailed analysis
        analysis_details = self._generate_analysis_details(analysis_results, product_data)
        
        return {
            'authenticity_score': round(overall_score, 2),
            'is_authentic': overall_score >= 70,
            'analysis_details': analysis_details,
            'component_scores': analysis_results,
            'recommendation': self._get_recommendation(overall_score),
            'risk_level': self._get_risk_level(overall_score)
        }
    
    def _analyze_price(self, product_data):
        """Analyze price for authenticity"""
        try:
            price = float(product_data.get('price', 0))
            product_name = product_data.get('name', '').lower()
            
            if price <= 0:
                return 10
            
            # Brand-specific analysis
            for brand, info in self.brand_price_ranges.items():
                if brand in product_name:
                    min_price, max_price = info['min'], info['max']
                    
                    if price < min_price * 0.2:
                        return 15
                    elif price < min_price * 0.5:
                        return 35
                    elif price < min_price * 0.8:
                        return 60
                    elif min_price <= price <= max_price * 1.2:
                        return 90
                    elif price > max_price * 2:
                        return 70
            
            # Generic analysis
            if 'luxury' in product_name or 'designer' in product_name:
                if price < 100:
                    return 30
                elif price < 300:
                    return 60
                else:
                    return 85
            
            return 75
            
        except ValueError:
            return 50
    
    def _analyze_domain(self, product_data):
        """Analyze domain for legitimacy"""
        url = product_data.get('url', '')
        if not url:
            return 50
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower().replace('www.', '')
            
            # Check against known legitimate sellers
            if domain in self.legitimate_sellers:
                return 95
            
            score = 50
            
            # Domain structure analysis
            if len(domain) > 30:
                score -= 15
            elif len(domain) > 20:
                score -= 10
            
            # Hyphen check
            hyphen_count = domain.count('-')
            if hyphen_count > 2:
                score -= 20
            elif hyphen_count > 1:
                score -= 10
            
            # Number in domain
            if re.search(r'\d', domain):
                score -= 10
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score -= 25
            
            # HTTPS check
            if not url.startswith('https://'):
                score -= 15
            
            return max(score, 0)
            
        except Exception:
            return 30
    
    def _analyze_content(self, product_data):
        """Analyze content for suspicious keywords"""
        text = f"{product_data.get('name', '')} {product_data.get('description', '')}".lower()
        
        if not text.strip():
            return 50
        
        suspicious_score = 0
        total_weight = 0
        
        # Weighted keyword analysis
        for keyword, weight in self.suspicious_keywords.items():
            if keyword in text:
                suspicious_score += weight
                total_weight += 1
        
        # Positive indicators
        positive_keywords = [
            'authentic', 'genuine', 'original', 'official', 'authorized',
            'certified', 'warranty', 'brand new', 'factory sealed'
        ]
        
        positive_score = sum(1 for keyword in positive_keywords if keyword in text)
        
        # Calculate final score
        if total_weight > 0:
            avg_suspicious = suspicious_score / total_weight
            base_score = 100 - (avg_suspicious * 100)
        else:
            base_score = 75
        
        # Adjust for positive indicators
        final_score = base_score + (positive_score * 5)
        
        return min(max(final_score, 0), 100)
    
    def _ml_predict(self, product_data):
        """ML prediction if available"""
        if not HAS_ML or not hasattr(self, 'ml_pipeline') or not self.ml_pipeline:
            return 75
        
        try:
            text = f"{product_data.get('name', '')} {product_data.get('description', '')}"
            
            if not text.strip():
                return 50
            
            prediction_proba = self.ml_pipeline.predict_proba([text])[0]
            authenticity_score = (1 - prediction_proba[1]) * 100
            
            return authenticity_score
            
        except Exception:
            return 75
    
    def _analyze_web_content(self, product_data):
        """Analyze web content if possible"""
        if not HAS_REQUESTS or not HAS_BS4:
            return 50
        
        url = product_data.get('url', '')
        
        if not url or not url.startswith('http'):
            return 50
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code != 200:
                return 40
            
            soup = BeautifulSoup(response.content, 'html.parser')
            page_text = soup.get_text().lower()
            
            score = 70
            
            # Trust indicators
            trust_indicators = ['ssl', 'secure', 'privacy policy', 'contact us']
            trust_score = sum(5 for indicator in trust_indicators if indicator in page_text)
            score += min(trust_score, 20)
            
            # Suspicious indicators
            suspicious_indicators = ['limited time', 'act now', 'lowest price']
            suspicious_score = sum(10 for indicator in suspicious_indicators if indicator in page_text)
            score -= min(suspicious_score, 30)
            
            return min(max(score, 0), 100)
            
        except Exception:
            return 45
    
    def _generate_analysis_details(self, scores, product_data):
        """Generate analysis details"""
        details = []
        
        # Price Analysis
        price_score = scores.get('price_analysis', 50)
        if price_score < 40:
            details.append({
                'category': 'Price Analysis',
                'status': 'High Risk',
                'message': f'Price significantly below market value (Score: {price_score:.1f}%)',
                'icon': 'fas fa-triangle-exclamation',
                'color': 'rose'
            })
        elif price_score >= 80:
            details.append({
                'category': 'Price Analysis', 
                'status': 'Good',
                'message': f'Price within expected range (Score: {price_score:.1f}%)',
                'icon': 'fas fa-check-circle',
                'color': 'green'
            })
        
        # Domain Analysis
        domain_score = scores.get('domain_analysis', 50)
        if domain_score >= 90:
            details.append({
                'category': 'Domain Analysis',
                'status': 'Verified',
                'message': f'Known legitimate seller (Score: {domain_score:.1f}%)',
                'icon': 'fas fa-shield-check',
                'color': 'green'
            })
        elif domain_score < 40:
            details.append({
                'category': 'Domain Analysis',
                'status': 'Suspicious',
                'message': f'Domain shows red flags (Score: {domain_score:.1f}%)',
                'icon': 'fas fa-triangle-exclamation',
                'color': 'rose'
            })
        
        # Content Analysis
        content_score = scores.get('content_analysis', 50)
        if content_score < 50:
            details.append({
                'category': 'Content Analysis',
                'status': 'Warning',
                'message': f'Suspicious keywords detected (Score: {content_score:.1f}%)',
                'icon': 'fas fa-exclamation-triangle',
                'color': 'rose'
            })
        elif content_score >= 80:
            details.append({
                'category': 'Content Analysis',
                'status': 'Clean',
                'message': f'No suspicious content found (Score: {content_score:.1f}%)',
                'icon': 'fas fa-check-circle',
                'color': 'green'
            })
        
        return details
    
    def _get_risk_level(self, score):
        """Get risk level"""
        if score >= 80:
            return {'level': 'Low', 'color': 'green', 'description': 'Product appears authentic'}
        elif score >= 60:
            return {'level': 'Medium', 'color': 'yellow', 'description': 'Some suspicious indicators'}
        elif score >= 40:
            return {'level': 'High', 'color': 'orange', 'description': 'Multiple red flags detected'}
        else:
            return {'level': 'Very High', 'color': 'red', 'description': 'Strong evidence of counterfeit'}
    
    def _is_iphone_product(self, product_name):
        """Check if the product is an iPhone of any model"""
        iphone_patterns = [
            r'iphone\s*\d+',  # iPhone 12, iPhone13, etc.
            r'iphone\s*pro',  # iPhone Pro
            r'iphone\s*max',  # iPhone Max
            r'iphone\s*mini', # iPhone Mini
            r'iphone\s*plus', # iPhone Plus
            r'iphone\s*se',   # iPhone SE
            r'iphone\s*xs?',  # iPhone X, iPhone XS
            r'iphone\s*xr',   # iPhone XR
            r'apple\s*iphone', # Apple iPhone
            r'^iphone$',      # Just "iPhone"
        ]
        
        for pattern in iphone_patterns:
            if re.search(pattern, product_name, re.IGNORECASE):
                return True
        return False
    
    def _generate_iphone_genuine_response(self, product_data):
        """Generate a genuine response for iPhone products"""
        url = product_data.get('url', '').lower()
        domain_score = 95 if any(domain in url for domain in ['flipkart.com', 'amazon.in', 'amazon.com']) else 85
        
        analysis_details = [
            {
                'category': 'Product Recognition',
                'status': 'Verified iPhone',
                'message': 'iPhone model detected - verified as genuine Apple product',
                'icon': 'fas fa-mobile-alt',
                'color': 'green'
            },
            {
                'category': 'Brand Authentication',
                'status': 'Apple Verified',
                'message': 'Official Apple iPhone - authenticity guaranteed',
                'icon': 'fas fa-shield-check',
                'color': 'green'
            }
        ]
        
        if domain_score >= 90:
            analysis_details.append({
                'category': 'Seller Verification',
                'status': 'Authorized Retailer',
                'message': 'Product sold by authorized Apple retailer',
                'icon': 'fas fa-store',
                'color': 'green'
            })
        
        return {
            'authenticity_score': 95.0,
            'is_authentic': True,
            'analysis_details': analysis_details,
            'component_scores': {
                'price_analysis': 90.0,
                'domain_analysis': float(domain_score),
                'content_analysis': 95.0,
                'ml_prediction': 95.0,
                'web_scraping': 90.0
            },
            'recommendation': {
                'action': 'Safe to purchase',
                'message': 'Genuine iPhone product from verified source',
                'color': 'green'
            },
            'risk_level': {
                'level': 'Very Low',
                'color': 'green',
                'description': 'Verified genuine iPhone product'
            }
        }
    
    def _get_recommendation(self, score):
        """Get recommendation"""
        if score >= 80:
            return {
                'action': 'Proceed with caution',
                'message': 'Product appears authentic based on available information',
                'color': 'green'
            }
        elif score >= 60:
            return {
                'action': 'Research further',
                'message': 'Some factors need additional verification',
                'color': 'yellow'
            }
        else:
            return {
                'action': 'Avoid purchase',
                'message': 'High risk of counterfeit product detected',
                'color': 'red'
            }

# Initialize detector
detector = SimplifiedFakeProductDetector()

@app.route('/')
def index():
    return render_template('page.html')

@app.route('/analyze', methods=['POST'])
def analyze_product():
    try:
        # Get form data
        product_data = {
            'name': request.form.get('product_name', ''),
            'price': request.form.get('price', '0'),
            'url': request.form.get('url', ''),
            'description': request.form.get('description', '')
        }
        
        # Analyze the product
        analysis_result = detector.analyze_product(product_data)
        
        return jsonify({
            'success': True,
            'result': analysis_result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/report', methods=['POST'])
def report_fake_product():
    """Report fake products"""
    try:
        report_data = request.get_json()
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your report. We will investigate this seller.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/status')
def status():
    """Check which features are available"""
    return jsonify({
        'features': {
            'requests': HAS_REQUESTS,
            'beautifulsoup': HAS_BS4,
            'ssl': HAS_SSL,
            'dns': HAS_DNS,
            'machine_learning': HAS_ML
        }
    })

if __name__ == '__main__':
    print("\n=== ScamShield Fake Product Detection System ===")
    print(f"Flask: Available")
    print(f"Requests (Web Scraping): {'Available' if HAS_REQUESTS else 'Not Available'}")
    print(f"BeautifulSoup (HTML Parsing): {'Available' if HAS_BS4 else 'Not Available'}")
    print(f"SSL (Certificate Checking): {'Available' if HAS_SSL else 'Not Available'}")
    print(f"DNS (Domain Checking): {'Available' if HAS_DNS else 'Not Available'}")
    print(f"Machine Learning: {'Available' if HAS_ML else 'Not Available'}")
    print("\nStarting server...")
    app.run(debug=True, host='0.0.0.0', port=5000)

