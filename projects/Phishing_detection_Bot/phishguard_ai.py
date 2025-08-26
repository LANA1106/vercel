import re
import random
import json
from urllib.parse import urlparse
import datetime
import logging
import os
from datetime import datetime
import argparse

# Configure logging to suppress network messages
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Disable network-related loggers
for logger_name in ['socket', 'urllib3', 'requests', 'connectionpool']:
    logging.getLogger(logger_name).setLevel(logging.CRITICAL)

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Safe URL analysis function
def safe_analyze_url(url):
    """Analyze a URL without making external lookups"""
    try:
        from utils.url_analyzer import analyze_url, URLAnalysisResult
        return analyze_url(url, disable_external=True, disable_network=True)
    except Exception:
        return None

# Check for enhanced URL analyzer
try:
    from utils.url_analyzer import URLAnalysisResult
    URL_ANALYZER_AVAILABLE = True
    print("Enhanced URL analysis module loaded")
except ImportError:
    URL_ANALYZER_AVAILABLE = False
    print("Warning: Enhanced URL analysis not available. Using basic analysis only.")

# Check for scikit-learn (but don't require it)
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.base import BaseEstimator, TransformerMixin
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.model_selection import train_test_split
    import pickle
    import numpy as np
    SKLEARN_AVAILABLE = True
    
    class SimpleTextExtractor(BaseEstimator, TransformerMixin):
        """Simple text extractor for sklearn pipeline"""
        def fit(self, X, y=None):
            return self
            
        def transform(self, X):
            if isinstance(X, (list, tuple)):
                return X
            return [X] if isinstance(X, str) else X
    
except ImportError:
    print("Warning: scikit-learn not available. Using rule-based analysis only.")
    SKLEARN_AVAILABLE = False

# Check for training data
try:
    from training_data import get_training_data, get_validation_data
    TRAINING_DATA_AVAILABLE = True
except ImportError:
    TRAINING_DATA_AVAILABLE = False

class PhishingDetectionChatbot:
    def __init__(self, name="User"):
        # Store user's name for personalization
        self.name = name
        
        # Initialize a simple ML model if scikit-learn is available
        self.model = None
        
        # Path for saving/loading the model
        self.model_path = "phishing_model.pkl"
        
        # Load or initialize ML model if sklearn is available
        if SKLEARN_AVAILABLE:
            self.initialize_model()
        else:
            print("Using rule-based analysis only (scikit-learn not available)")
        
        # Phishing indicators and regex patterns
        self.urgent_phrases = [
            "act now", "urgent", "immediate action", "expires soon", 
            "account suspended", "verify your account", "account will be locked",
            "security alert", "unauthorized access", "suspicious activity"
        ]
        
        self.sensitive_info_patterns = [
            r"password", r"login", r"credit card", r"ssn", r"social security",
            r"bank account", r"pin", r"security question", r"verify your identity"
        ]
        
        self.url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        
        # Known phishing domains (would be regularly updated in production)
        self.suspicious_domains = [
            "paypa1.com", "amaz0n.com", "secure-payments", "login-verify",
            "account-update", "bankofamerica-secure", "apple-id-verify"
        ]
        
        # Enhanced educational content with more comprehensive information
        self.phishing_education = {
            "what is phishing": "🎣 **Phishing Explained:**\n\nPhishing is a cybercrime where attackers impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, or personal data. They create convincing fake websites, emails, or messages that appear to be from trusted sources.\n\n**Common Types:**\n• Email phishing (most common)\n• SMS phishing (smishing)\n• Voice call phishing (vishing)\n• Social media phishing\n• Fake websites and ads\n\n**Why it works:** Phishers exploit human psychology, using urgency, fear, and trust to bypass logical thinking.",
            
            "how to recognize phishing": "🔍 **How to Spot Phishing Attempts:**\n\n**Email Red Flags:**\n1. Generic greetings ('Dear Customer')\n2. Urgent language creating pressure\n3. Poor grammar and spelling errors\n4. Mismatched sender addresses\n5. Suspicious links (hover to preview)\n6. Unexpected attachments\n7. Requests for personal information\n\n**URL Red Flags:**\n• Misspelled domain names\n• Suspicious top-level domains (.tk, .ml)\n• Extra subdomains (paypal.secure-site.com)\n• HTTP instead of HTTPS\n• Shortened URLs hiding destination\n\n**Always verify independently through official channels!**",
            
            "phishing red flags": "🚩 **Major Phishing Red Flags:**\n\n**Language Patterns:**\n• 'Urgent action required!'\n• 'Account will be suspended!'\n• 'Click here immediately!'\n• 'Verify your information now!'\n• 'You've won a prize!'\n• 'Suspicious activity detected!'\n\n**Technical Red Flags:**\n• Links don't match legitimate domains\n• Poor website design or formatting\n• No secure padlock icon (HTTPS)\n• Requests for passwords via email\n• Attachments from unknown senders\n\n**Trust your instincts - if something feels wrong, it probably is!**",
            
            "protect from phishing": "🛡️ **Complete Phishing Protection Guide:**\n\n**Technical Defenses:**\n1. Enable multi-factor authentication (MFA)\n2. Use a password manager\n3. Keep software and browsers updated\n4. Install reputable antivirus software\n5. Use email filters and spam protection\n\n**Behavioral Defenses:**\n6. Never click suspicious links or attachments\n7. Verify requests through official channels\n8. Check URLs carefully before entering data\n9. Be skeptical of unexpected contacts\n10. Report suspicious emails to IT/authorities\n\n**Advanced Tips:**\n• Use different emails for different purposes\n• Regularly monitor account statements\n• Set up account alerts for suspicious activity",
            
            "social engineering": "🧠 **Social Engineering Tactics:**\n\nPhishers are expert manipulators who exploit human psychology:\n\n**Authority:** Impersonating banks, government, or your boss\n**Urgency:** Creating fake deadlines and emergencies\n**Fear:** Threatening account closure or legal action\n**Scarcity:** Limited-time offers or exclusive deals\n**Social Proof:** 'Everyone else has already done this'\n**Reciprocity:** Offering something 'free' first\n\n**Defense:** Slow down, verify independently, and trust your gut!",
            
            "business email compromise": "💼 **Business Email Compromise (BEC):**\n\nA sophisticated attack targeting businesses:\n\n**How it works:**\n• Criminals research company structure\n• Impersonate executives or vendors\n• Request wire transfers or data\n• Often bypass technical controls\n\n**Protection:**\n• Verify requests via phone\n• Implement approval processes\n• Train employees on BEC tactics\n• Use email authentication (DKIM, SPF)",
            
            "password security": "🔐 **Password Security Best Practices:**\n\n**Strong Passwords:**\n• 12+ characters with mixed case, numbers, symbols\n• Unique for every account\n• No personal information\n• No dictionary words\n\n**Password Manager Benefits:**\n• Generates strong passwords\n• Stores them securely\n• Auto-fills safely\n• Warns about breaches\n\n**Multi-Factor Authentication:**\n• Something you know (password)\n• Something you have (phone/token)\n• Something you are (fingerprint)",
            
            "incident response": "🚨 **If You've Been Phished:**\n\n**Immediate Actions:**\n1. Change all affected passwords immediately\n2. Contact your bank/credit card companies\n3. Monitor account statements closely\n4. Run antivirus scans\n5. Report to authorities (FBI IC3, FTC)\n\n**Damage Control:**\n• Check credit reports\n• Set up fraud alerts\n• Document everything\n• Learn from the experience\n\n**Prevention Going Forward:**\n• Enable all security features\n• Be more vigilant\n• Educate family/colleagues"
        }
        
        # Enhanced quiz questions with more scenarios and difficulty levels
        self.phishing_quiz = [
            {
                "question": "You receive an email claiming to be from your bank requesting your password. What should you do?",
                "options": ["Reply with the password", "Click on any links and provide the information", "Contact your bank directly using the official phone number or website", "Forward the email to friends to see if they got the same email"],
                "correct": 2,
                "explanation": "✅ Correct! Legitimate banks will NEVER ask for passwords via email. Always verify through official channels. Real banks have secure systems that don't require email password requests.",
                "level": "beginner"
            },
            {
                "question": "Which of these URLs is most likely legitimate?",
                "options": ["www.paypa1.com/secure", "security-paypal.com/login", "paypal.com/login", "paypal-secure.tk/account"],
                "correct": 2,
                "explanation": "✅ Correct! Only 'paypal.com/login' uses the official domain. The others use typosquatting (paypa1), subdomain abuse (security-paypal), or suspicious TLDs (.tk).",
                "level": "beginner"
            },
            {
                "question": "What should you do before clicking a link in an email?",
                "options": ["Click it to see where it goes", "Hover over it to preview the actual URL", "Immediately report the email as phishing", "Download any attachments first"],
                "correct": 1,
                "explanation": "✅ Correct! Hovering reveals the real destination without clicking. This is a crucial safety step that can prevent malware infections and credential theft.",
                "level": "beginner"
            },
            {
                "question": "A colleague sends you an urgent email asking for company financial data, but the tone seems unusual. What's your best response?",
                "options": ["Send the data immediately since it's urgent", "Call or message the colleague directly to verify the request", "Reply asking for more details via email", "Ignore the email completely"],
                "correct": 1,
                "explanation": "✅ Correct! This could be Business Email Compromise (BEC). Always verify unusual requests through a different communication channel, especially for sensitive data.",
                "level": "intermediate"
            },
            {
                "question": "You receive a text message with a link claiming you've won a prize. The link goes to 'apple-rewards.secure-offer.com'. What's wrong?",
                "options": ["Nothing, it's from Apple", "The domain isn't apple.com", "Text messages can't contain links", "Apple doesn't give away prizes"],
                "correct": 1,
                "explanation": "✅ Correct! Legitimate Apple communications come from apple.com domains. This is subdomain abuse - a common phishing technique using official brand names in fake subdomains.",
                "level": "intermediate"
            },
            {
                "question": "An email claims your account was accessed from Russia and includes a 'secure login' link. The email headers show 'Return-Path: noreply@security-alerts.info'. What's suspicious?",
                "options": ["Nothing, security alerts are normal", "The Return-Path domain doesn't match the claimed sender", "Russia isn't a suspicious location", "The timing of the email"],
                "correct": 1,
                "explanation": "✅ Correct! Advanced phishing often uses mismatched Return-Path headers. Legitimate services use consistent domains in all email headers.",
                "level": "advanced"
            },
            {
                "question": "Which multi-factor authentication method is most secure?",
                "options": ["SMS codes", "Email codes", "Authenticator app with TOTP", "Security questions"],
                "correct": 2,
                "explanation": "✅ Correct! Authenticator apps with TOTP (Time-based One-Time Passwords) are most secure as they work offline and can't be intercepted like SMS or email codes.",
                "level": "advanced"
            },
            {
                "question": "You notice a colleague's email account is sending spam to everyone. What likely happened?",
                "options": ["Their computer has a virus", "They're deliberately sending spam", "Their email account was compromised", "It's just a technical glitch"],
                "correct": 2,
                "explanation": "✅ Correct! When legitimate accounts send spam, they're usually compromised through phishing, password reuse, or data breaches. The colleague needs to secure their account immediately.",
                "level": "intermediate"
            }
        ]
        
        # Greeting and conversation phrases
        self.greetings = ["hello", "hi", "hey", "greetings", "good morning", "good afternoon", "good evening"]
        self.goodbye_phrases = ["bye", "goodbye", "see you", "exit", "quit", "end"]
        
        # Enhanced conversation state with more context tracking
        self.conversation_context = {
            "in_quiz": False,
            "current_quiz": None,
            "quiz_state": 0,
            "quiz_score": 0,
            "quiz_count": 0,
            "last_topic": None,
            "user_expertise": "beginner",  # beginner, intermediate, advanced
            "conversation_history": [],
            "recent_analyses": [],
            "learning_path": []
        }
        
        # Add email-specific patterns
        self.email_suspicious_patterns = [
            r"verify.*account",
            r"confirm.*password",
            r"update.*information",
            r"security.*alert",
            r"unauthorized.*access",
            r"suspicious.*activity",
            r"account.*suspended",
            r"click.*here",
            r"verify.*identity",
            r"confirm.*details"
        ]
        
        self.email_headers_to_check = [
            'From',
            'Reply-To',
            'Return-Path',
            'X-Mailer',
            'Message-ID'
        ]
    
    def initialize_model(self):
        """Initialize the machine learning model for phishing detection."""
        try:
            # Try to load an existing model
            if os.path.exists(self.model_path):
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                print("✓ Loaded existing phishing detection model")
            else:
                # Create a simple text classification model without complex dependencies
                self.model = Pipeline([
                    ('vectorizer', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
                    ('classifier', RandomForestClassifier(n_estimators=50, random_state=42))
                ])
                print("✓ Created new phishing detection model (untrained)")
                
                # Don't auto-train to avoid initialization issues
                print("Note: Model will use rule-based analysis until trained with data")
        except Exception as e:
            print(f"Warning: Could not initialize ML model: {e}")
            self.model = None
    
    def train_model(self, use_csv=True, X_train=None, y_train=None, sample_size=10000):
        """Train the phishing detection model with provided or default training data."""
        if not SKLEARN_AVAILABLE:
            print("Cannot train model: scikit-learn is not available.")
            return False
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_file = f"phishing_model_{timestamp}.pkl"
            
            # Use provided training data or get default training data
            if X_train is None or y_train is None:
                if not TRAINING_DATA_AVAILABLE:
                    print("Cannot train model: No training data available.")
                    return False
                
                print("Loading training data...")
                
                if use_csv:
                    print(f"Using CSV dataset (sample size: {sample_size if sample_size else 'all'})...")
                    try:
                        training_data = get_training_data(use_csv=True, sample_size=sample_size)
                        
                        if len(training_data) == 4:
                            # Text-only format (fallback)
                            X_train_text, X_test_text, y_train, y_test = training_data
                            print("Using text samples only (CSV loading failed)")
                            
                            X_train = X_train_text
                            csv_available = False
                        else:
                            # Full format with both text and CSV data
                            (X_train_text, X_test_text), (X_train_url, X_test_url), (y_train_text, y_test_text), (y_train_url, y_test_url), feature_names, _ = training_data
                            
                            print(f"Text samples: {len(X_train_text)} training, {len(X_test_text)} testing")
                            print(f"URL samples: {len(X_train_url)} training, {len(X_test_url)} testing")
                            
                            # For training, we'll use the URL dataset with its labels
                            X_train = ((X_train_text, X_train_url))
                            y_train = y_train_url
                            
                            # For testing, we'll use the URL dataset with its labels
                            X_test = ((X_test_text, X_test_url))
                            y_test = y_test_url
                            
                            csv_available = True
                    except Exception as e:
                        print(f"Error processing CSV data: {e}")
                        X_train, X_test, y_train, y_test = get_training_data(use_csv=False)
                        csv_available = False
                else:
                    # Text-only samples
                    X_train, X_test, y_train, y_test = get_training_data(use_csv=False)
                    csv_available = False
            else:
                # Using provided data
                csv_available = isinstance(X_train, tuple) and len(X_train) >= 2
                X_test = None
                y_test = None
            
            # Create a simple text classification model
            print("Creating simplified text classification model...")
            self.model = Pipeline([
                ('vectorizer', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
                ('classifier', RandomForestClassifier(n_estimators=50, random_state=42))
            ])
            
            # Train the model
            print(f"Training phishing detection model...")
            self.model.fit(X_train, y_train)
            # Evaluate on training data
            y_pred = self.model.predict(X_train)
            train_accuracy = accuracy_score(y_train, y_pred)
            print(f"Training accuracy: {train_accuracy:.2f}")
            
            # Evaluate on validation data if available
            if TRAINING_DATA_AVAILABLE:
                X_val, y_val = get_validation_data()
                val_pred = self.model.predict(X_val)
                val_accuracy = accuracy_score(y_val, val_pred)
                print(f"Validation accuracy: {val_accuracy:.2f}")
                
                # Display detailed performance metrics
                print("\nModel Performance Report:")
                print(classification_report(y_val, val_pred, target_names=["Legitimate", "Phishing"]))
                
                # Display confusion matrix
                cm = confusion_matrix(y_val, val_pred)
                print("\nConfusion Matrix:")
                print("               Predicted      ")
                print("               Legitimate  Phishing")
                print(f"Actual Legitimate  {cm[0][0]}          {cm[0][1]}")
                print(f"      Phishing    {cm[1][0]}          {cm[1][1]}")
            
            # Save the trained model
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)
            print(f"✓ Model saved to {self.model_path}")
            
            return True
            
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def get_educational_content(self, query):
        """Retrieve educational content based on user query."""
        query = query.lower()
        
        # Direct match with educational content
        for key, content in self.phishing_education.items():
            if query in key or key in query:
                return content
        
        # Simple keyword matching for finding relevant content
        education_scores = {}
        query_words = query.lower().split()
        
        for key, content in self.phishing_education.items():
            key_words = key.lower().split()
            common_words = set(query_words).intersection(set(key_words))
            education_scores[key] = len(common_words)
        
        if education_scores:
            best_match = max(education_scores.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                return self.phishing_education[best_match[0]]
        
        # Default response if no match found
        return "I can provide information about phishing, how to recognize it, common red flags, and how to protect yourself. What would you like to learn more about?"
    
    def start_quiz(self):
        """Start an interactive phishing awareness quiz."""
        self.conversation_context["in_quiz"] = True
        self.conversation_context["quiz_state"] = 0
        self.conversation_context["current_quiz"] = random.choice(self.phishing_quiz)
        
        quiz = self.conversation_context["current_quiz"]
        question_text = quiz["question"]
        options_text = "\n".join([f"{i+1}. {option}" for i, option in enumerate(quiz["options"])])
        
        return f"Let's test your phishing awareness!\n\n{question_text}\n\n{options_text}\n\nPlease enter the number of your answer."
    
    def handle_quiz_response(self, user_input):
        """Process user response during a quiz."""
        if not self.conversation_context["in_quiz"]:
            return "No quiz is currently active. Type 'start quiz' to begin one!"
        
        quiz = self.conversation_context["current_quiz"]
        try:
            user_answer = int(user_input.strip()) - 1  # Convert to 0-based index
            if 0 <= user_answer < len(quiz["options"]):
                is_correct = user_answer == quiz["correct"]
                self.conversation_context["in_quiz"] = False  # End quiz
                
                if is_correct:
                    result = "✅ Correct! "
                else:
                    result = f"❌ Incorrect. The correct answer is: {quiz['options'][quiz['correct']]}. "
                
                return result + quiz["explanation"] + "\n\nWould you like to try another quiz question?"
            else:
                return f"Please enter a number between 1 and {len(quiz['options'])}."
        except ValueError:
            # User didn't enter a number
            if user_input.lower() in ["quit quiz", "exit quiz", "stop"]:
                self.conversation_context["in_quiz"] = False
                return "Quiz stopped. What would you like to do now?"
            else:
                return f"Please enter the number of your answer (1-{len(quiz['options'])})."

    def get_smart_recommendations(self):
        """Generate personalized recommendations based on user's learning progress."""
        recommendations = []
        
        # Based on quiz performance
        if self.conversation_context["quiz_count"] > 0:
            accuracy = self.conversation_context["quiz_score"] / self.conversation_context["quiz_count"]
            if accuracy < 0.7:
                recommendations.append("📚 I notice you might benefit from reviewing phishing basics. Try asking about 'how to recognize phishing'.")
            elif accuracy > 0.9:
                recommendations.append("🎓 You're doing great! Ready for advanced topics like 'business email compromise' or 'social engineering'?")
        
        # Based on recent analyses
        if len(self.conversation_context["recent_analyses"]) > 0:
            high_risk_count = sum(1 for analysis in self.conversation_context["recent_analyses"] if analysis.get("risk_level") == "High")
            if high_risk_count > 0:
                recommendations.append("🛡️ You've encountered high-risk content. Consider learning about 'incident response' to know what to do if you're targeted.")
        
        # Based on expertise level
        if self.conversation_context["user_expertise"] == "beginner":
            recommendations.append("🌟 Start with the basics: Ask me 'what is phishing' or take a beginner quiz!")
        elif self.conversation_context["user_expertise"] == "advanced":
            recommendations.append("🔬 Ready for advanced scenarios? Try asking about 'homograph attacks' or 'advanced persistent threats'.")
        
        return recommendations
    
    def update_user_expertise(self, quiz_performance, analysis_complexity):
        """Dynamically update user expertise level based on interactions."""
        current_level = self.conversation_context["user_expertise"]
        
        # Upgrade based on quiz performance
        if quiz_performance > 0.8 and current_level == "beginner":
            self.conversation_context["user_expertise"] = "intermediate"
        elif quiz_performance > 0.9 and current_level == "intermediate":
            self.conversation_context["user_expertise"] = "advanced"
        
        # Downgrade if struggling
        elif quiz_performance < 0.5 and current_level == "advanced":
            self.conversation_context["user_expertise"] = "intermediate"
        elif quiz_performance < 0.3 and current_level == "intermediate":
            self.conversation_context["user_expertise"] = "beginner"
    
    def get_learning_stats(self):
        """Get learning statistics for the user."""
        try:
            stats = {
                "quiz_count": self.conversation_context.get("quiz_count", 0),
                "quiz_score": self.conversation_context.get("quiz_score", 0),
                "user_expertise": self.conversation_context.get("user_expertise", "beginner"),
                "analyses_performed": len(self.conversation_context.get("recent_analyses", [])),
                "conversation_count": len(self.conversation_context.get("conversation_history", [])),
                "last_topic": self.conversation_context.get("last_topic", "None")
            }
            
            # Calculate accuracy if quizzes have been taken
            if stats["quiz_count"] > 0:
                stats["quiz_accuracy"] = round((stats["quiz_score"] / stats["quiz_count"]) * 100, 1)
            else:
                stats["quiz_accuracy"] = 0
            
            return stats
            
        except Exception as e:
            # Return default stats on error
            return {
                "quiz_count": 0,
                "quiz_score": 0,
                "quiz_accuracy": 0,
                "user_expertise": "beginner",
                "analyses_performed": 0,
                "conversation_count": 0,
                "last_topic": "None",
                "error": str(e)
            }
    
    def get_contextual_response(self, user_input):
        """Generate contextually aware responses based on conversation history."""
        input_lower = user_input.lower()
        
        # Handle follow-up questions
        if self.conversation_context["last_topic"]:
            follow_up_phrases = ["tell me more", "what else", "continue", "more info", "explain further", "details"]
            if any(phrase in input_lower for phrase in follow_up_phrases):
                last_topic = self.conversation_context["last_topic"]
                if last_topic in self.phishing_education:
                    return f"Let me elaborate on {last_topic}:\n\n{self.phishing_education[last_topic]}\n\nWould you like to explore any specific aspect in more detail?"
        
        # Handle clarification requests
        clarification_phrases = ["what do you mean", "explain", "clarify", "don't understand", "confused"]
        if any(phrase in input_lower for phrase in clarification_phrases):
            return "I'd be happy to clarify! Could you tell me which part you'd like me to explain in simpler terms? I can break down complex security concepts into easier-to-understand explanations."
        
        # Handle improvement requests
        improvement_phrases = ["how can i improve", "get better", "learn more", "next steps"]
        if any(phrase in input_lower for phrase in improvement_phrases):
            recommendations = self.get_smart_recommendations()
            if recommendations:
                return "Here are some personalized suggestions for you:\n\n" + "\n".join(recommendations)
            else:
                return "Great question! Based on our conversation, I'd recommend starting with phishing awareness quizzes and learning about common attack patterns. What specific area interests you most?"
        
        return None
    
    def get_response(self, message):
        """Main method for getting chatbot responses - used by Flask app"""
        return self.generate_response(message)
    
    def analyze_message(self, message):
        """Analyze a message for phishing indicators - used by Flask app"""
        return self.analyze_text_for_phishing(message)
    
    def analyze_url_for_api(self, url):
        """Analyze a URL for phishing indicators - used by Flask app"""
        risk_score, reason = self.analyze_url_internal(url)
        return {
            "risk_score": risk_score,
            "risk_level": "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low" if risk_score > 0 else "Minimal",
            "reason": reason
        }
    
    def generate_response(self, user_input):
        """Enhanced response generation with context awareness and personalization."""
        # Add to conversation history
        self.conversation_context["conversation_history"].append(user_input)
        
        # Keep only last 10 interactions for context
        if len(self.conversation_context["conversation_history"]) > 10:
            self.conversation_context["conversation_history"] = self.conversation_context["conversation_history"][-10:]
        
        # Check for contextual responses first
        contextual_response = self.get_contextual_response(user_input)
        if contextual_response:
            return contextual_response
        
        # Handle active quiz
        if self.conversation_context["in_quiz"]:
            if user_input.lower() in ["exit quiz", "quit quiz", "stop quiz"]:
                self.conversation_context["in_quiz"] = False
                return "Quiz stopped. You can start a new one anytime by typing 'quiz'."
                
            if user_input.lower() in ["yes", "y", "next", "continue"]:
                return self.start_quiz()
            elif user_input.lower() in ["no", "n", "stop"]:
                self.conversation_context["in_quiz"] = False
                return "Quiz stopped. You can continue learning about phishing prevention or take another quiz later."
            else:
                # Handle quiz answer
                response = self.handle_quiz_response(user_input)
                
                # Update expertise based on quiz performance
                if self.conversation_context["quiz_count"] > 0:
                    performance = self.conversation_context["quiz_score"] / self.conversation_context["quiz_count"]
                    self.update_user_expertise(performance, "basic")
                
                return response
        
        # Enhanced quiz commands with difficulty selection
        quiz_patterns = {
            "beginner quiz": "beginner",
            "easy quiz": "beginner", 
            "intermediate quiz": "intermediate",
            "advanced quiz": "advanced",
            "hard quiz": "advanced",
            "quiz": None,
            "start quiz": None,
            "test me": None,
            "take quiz": None
        }
        
        for pattern, level in quiz_patterns.items():
            if pattern in user_input.lower():
                if level:
                    # Filter quizzes by difficulty level
                    available_quizzes = [q for q in self.phishing_quiz if q.get("level") == level]
                    if available_quizzes:
                        self.conversation_context["current_quiz"] = random.choice(available_quizzes)
                    else:
                        self.conversation_context["current_quiz"] = random.choice(self.phishing_quiz)
                return self.start_quiz()
        
        # Enhanced educational content with context tracking
        for key in self.phishing_education:
            if key in user_input.lower() or any(word in user_input.lower() for word in key.split()):
                self.conversation_context["last_topic"] = key
                response = self.get_educational_content(user_input)
                
                # Add personalized follow-up suggestions
                if key == "what is phishing":
                    response += "\n\n💡 Next, you might want to learn about 'how to recognize phishing' or take a beginner quiz!"
                elif key == "how to recognize phishing":
                    response += "\n\n💡 Ready to test your knowledge? Try a quiz or learn about 'phishing red flags'!"
                elif key == "protect from phishing":
                    response += "\n\n💡 Want to dive deeper? Ask about 'password security' or 'multi-factor authentication'!"
                
                return response
        
        # Enhanced message analysis with learning integration
        analyze_indicators = ["check", "analyze", "scan", "is this", "phishing", "suspicious", "safe"]
        if any(indicator in user_input.lower() for indicator in analyze_indicators) and len(user_input) > 20:
            try:
                analysis = self.analyze_text_for_phishing(user_input)
                
                # Store analysis for learning purposes
                self.conversation_context["recent_analyses"].append(analysis)
                if len(self.conversation_context["recent_analyses"]) > 5:
                    self.conversation_context["recent_analyses"] = self.conversation_context["recent_analyses"][-5:]
                
                response = f"🔍 **Analysis Results:**\n\n📊 Risk Level: {analysis['risk_level']} (Score: {analysis['risk_score']}/100)\n\n"
                
                if analysis['risk_factors']:
                    response += "⚠️ **Risk Factors Detected:**\n"
                    for i, factor in enumerate(analysis['risk_factors'], 1):
                        response += f"{i}. {factor}\n"
                else:
                    response += "✅ **No significant risk factors detected.**\n"
                
                response += "\n"
                
                # Add educational insights based on findings
                if "URL" in " ".join(analysis['risk_factors']):
                    response += "💡 **Security Tip:** Always verify URLs by hovering over links before clicking. Look for HTTPS and the correct domain name.\n\n"
                
                if "sensitive information" in " ".join(analysis['risk_factors']):
                    response += "🛡️ **Important:** Legitimate organizations never ask for passwords or full credit card details via email.\n\n"
                
                if "urgent" in " ".join(analysis['risk_factors']):
                    response += "⏰ **Be Aware:** Phishing attempts create false urgency to make you act without thinking.\n\n"
                
                # Personalized recommendations based on risk level
                if analysis['risk_level'] == "High":
                    response += "🚨 **This appears to be a phishing attempt!** Do not click any links or provide information. Would you like to learn about 'incident response'?"
                elif analysis['risk_level'] == "Medium":
                    response += "⚠️ **Exercise caution with this message.** When in doubt, verify through official channels. Want tips on 'how to verify suspicious messages'?"
                elif analysis['risk_level'] == "Low":
                    response += "😊 **This seems relatively safe, but stay vigilant!** Would you like to test your skills with a phishing quiz?"
                else:
                    response += "✅ **This appears safe!** Keep practicing your phishing detection skills - want to try analyzing another message?"
                
                return response
            except Exception as e:
                return f"❌ I encountered an error analyzing your message: {str(e)}. Please try again with a different message."
        
        # Handle help and capability questions
        help_phrases = ["help", "what can you do", "capabilities", "features", "commands"]
        if any(phrase in user_input.lower() for phrase in help_phrases):
            expertise_level = self.conversation_context["user_expertise"]
            response = f"🤖 **PhishGuard AI Capabilities** (Your level: {expertise_level.title()}):\n\n"
            response += "🔍 **Analysis Features:**\n• Analyze suspicious messages and emails\n• Check URLs for phishing indicators\n• Detect social engineering tactics\n\n"
            response += "📚 **Educational Content:**\n• Learn about phishing techniques\n• Understand protection strategies\n• Get personalized security tips\n\n"
            response += "🎯 **Interactive Learning:**\n• Take skill-appropriate quizzes\n• Practice with real-world scenarios\n• Track your learning progress\n\n"
            response += "💬 **Smart Conversation:**\n• Context-aware responses\n• Personalized recommendations\n• Follow-up explanations\n\n"
            
            recommendations = self.get_smart_recommendations()
            if recommendations:
                response += "💡 **Suggestions for you:**\n" + "\n".join(recommendations)
            
            return response
        
        # Handle greetings with personalization
        if user_input.lower() in self.greetings or any(greeting in user_input.lower() for greeting in self.greetings):
            expertise = self.conversation_context["user_expertise"]
            time_of_day = datetime.now().hour
            
            if time_of_day < 12:
                greeting = "Good morning"
            elif time_of_day < 17:
                greeting = "Good afternoon"
            else:
                greeting = "Good evening"
            
            response = f"{greeting} {self.name}! 👋 I'm your AI cybersecurity assistant.\n\n"
            
            if expertise == "beginner":
                response += "🌟 I see you're new to cybersecurity. Perfect! I'll help you learn the basics step by step."
            elif expertise == "intermediate":
                response += "👍 You have some security knowledge. Let's build on that foundation!"
            else:
                response += "🎓 I can see you're quite knowledgeable about security. Ready for some advanced topics?"
            
            response += "\n\n🎯 **What would you like to do?**\n"
            response += "• Analyze a suspicious message\n"
            response += "• Learn about phishing techniques\n"
            response += f"• Take a {expertise}-level quiz\n"
            response += "• Get personalized security tips\n"
            
            return response
        
        # Handle goodbyes with security reminders
        if any(goodbye in user_input.lower() for goodbye in self.goodbye_phrases):
            tips = [
                "Remember: When in doubt, verify independently!",
                "Stay vigilant: Phishers are always evolving their tactics.",
                "Security tip: Use different passwords for all your accounts.",
                "Remember: Legitimate companies won't ask for passwords via email.",
                "Stay safe: Always check URLs before clicking!"
            ]
            tip = random.choice(tips)
            return f"Goodbye {self.name}! 👋\n\n🛡️ {tip}\n\nStay safe online, and feel free to come back anytime for security advice!"
        
        # Handle unknown inputs with intelligent suggestions
        unknown_responses = [
            f"I'm not sure I understand, {self.name}. Let me help you explore what I can do!",
            f"That's an interesting question, {self.name}! Let me suggest some things I can help with.",
            f"I want to make sure I give you the best help, {self.name}. Here's what I specialize in:"
        ]
        
        response = random.choice(unknown_responses)
        response += "\n\n🎯 **Try asking me about:**\n"
        response += "• 'What is phishing?' - Learn the basics\n"
        response += "• 'How to recognize phishing?' - Spot the signs\n"
        response += "• 'Check this message: [paste message]' - Analyze content\n"
        response += "• 'Quiz' - Test your knowledge\n"
        response += "• 'Help' - See all my capabilities\n\n"
        
        # Add smart recommendations
        recommendations = self.get_smart_recommendations()
        if recommendations:
            response += "💡 **Personalized suggestions:**\n" + "\n".join(recommendations[:2])  # Show top 2
        
        return response
    
    def analyze_text_for_phishing(self, text):
        """Analyze input text for signs of phishing."""
        text_score = 0
        url_score = 0
        risk_factors = []
        suspicious_urls = []
        url_analysis_results = []
        
        # Convert text to lowercase for analysis
        text_lower = text.lower()
        
        # Check for urgent language
        urgent_count = sum(1 for phrase in self.urgent_phrases if phrase in text_lower)
        if urgent_count > 0:
            text_score += min(urgent_count * 10, 30)  # Cap at 30 points
            risk_factors.append(f"Detected {urgent_count} urgent phrases creating a sense of pressure")
        
        # Check for requests for sensitive information
        sensitive_count = 0
        for pattern in self.sensitive_info_patterns:
            if re.search(pattern, text_lower):
                sensitive_count += 1
        
        if sensitive_count > 0:
            text_score += min(sensitive_count * 15, 30)  # Cap at 30 points
            risk_factors.append(f"Detected {sensitive_count} requests for sensitive information")
        
        # Extract and analyze URLs
        urls = re.findall(self.url_pattern, text)
        
        for url in urls:
            # Use the enhanced URL analysis if available
            if URL_ANALYZER_AVAILABLE:
                try:
                    # Use our safe wrapper to avoid external lookups
                    analysis_result = safe_analyze_url(url)
                    
                    # If the wrapper returned None, fallback to basic analysis
                    if analysis_result is None:
                        # Use basic analysis without external dependencies
                        url_risk, url_reason = self.analyze_url_internal(url)
                        url_score += url_risk
                        if url_risk > 0:
                            suspicious_urls.append(f"{url}: {url_reason}")
                    else:
                        url_analysis_results.append(analysis_result)
                        
                        # Add to URL score based on the URL analysis score
                        url_risk = int(analysis_result.score * 40)  # Scale the 0-1 score to 0-40
                        url_score += url_risk
                        
                        # Add detailed information about suspicious URLs
                        if analysis_result.is_suspicious:
                            elements = "; ".join(analysis_result.suspicious_elements[:3])  # Limit to top 3 for readability
                            suspicious_urls.append(f"{url}: {elements}")
                except Exception:
                    # Silently use fallback without logging errors
                    url_risk, url_reason = self.analyze_url_internal(url)
                    url_score += url_risk
                    if url_risk > 0:
                        suspicious_urls.append(f"{url}: {url_reason}")
            else:
                # Use the basic URL analysis
                url_risk, url_reason = self.analyze_url_internal(url)
                url_score += url_risk
                if url_risk > 0:
                    suspicious_urls.append(f"{url}: {url_reason}")
        
        if suspicious_urls:
            risk_factors.append("Suspicious URLs detected: " + "; ".join(suspicious_urls))
            
        # Store the URL analysis results for detailed reporting
        self.last_url_analysis = url_analysis_results
        
        # Rule-based sentiment analysis
        try:
            # Use enhanced emotion detection with more comprehensive word lists
            negative_words = ["urgent", "alert", "warning", "problem", "suspicious", "unauthorized", "fraud", 
                            "threat", "danger", "risk", "compromise", "breach", "illegal", "criminal", 
                            "emergency", "critical", "severe", "malicious", "harmful", "violate", "restricted"]
            negative_count = sum(1 for word in negative_words if word in text_lower)
            
            positive_manipulation_words = ["exclusive", "limited", "special", "bonus", "free", "reward", "prize", 
                                         "congratulations", "selected", "winner", "discount", "offer", "opportunity", 
                                         "guaranteed", "instant", "approved", "qualified", "eligible"]
            positive_count = sum(1 for word in positive_manipulation_words if word in text_lower)
            
            if negative_count >= 2:
                text_score += 15
                risk_factors.append(f"Contains {negative_count} words creating negative emotions or urgency")
            
            if positive_count >= 2:
                text_score += 15
                risk_factors.append(f"Contains {positive_count} words with positive manipulation")
                
            # Extra points for combining both manipulation techniques
            if negative_count >= 1 and positive_count >= 1:
                text_score += 10
                risk_factors.append("Combines both fear tactics and positive manipulation")
        except Exception as e:
            print(f"Sentiment analysis error: {e}")
            
        # Check for common phishing text patterns
        phishing_patterns = [
            (r"verify your account|confirm your details|unusual activity", 15, "Contains typical phishing phrases"),
            (r"won .*(prize|lottery|giveaway)", 25, "Potential prize scam detected"),
            (r"click here|click now|act now", 10, "Contains urgent call-to-action phrases"),
            (r"suspended|locked|blocked|frozen", 15, "Contains account threat language"),
            (r"congratulations|winner|selected|chosen", 12, "Contains prize/lottery language"),
            (r"limited time|expires|deadline|urgent", 10, "Creates false urgency"),
            (r"confirm.*(password|identity|account)", 20, "Requests credential confirmation"),
            (r"update.*(payment|billing|card)", 18, "Requests payment information update"),
            (r"security.*(alert|warning|notice)", 12, "Uses security scare tactics"),
            (r"dear (customer|user|member)", 8, "Uses generic greeting")
        ]
        
        for pattern, points, description in phishing_patterns:
            if re.search(pattern, text_lower):
                text_score += points
                risk_factors.append(description)
        
        # Cap individual scores at 100
        text_score = min(text_score, 100)
        url_score = min(url_score, 100)
        
        # Calculate combined score (weighted average)
        if urls:
            # If URLs are present, weight URL score more heavily
            combined_score = (text_score * 0.4) + (url_score * 0.6)
        else:
            # If no URLs, use text score only
            combined_score = text_score
        
        # Cap combined score at 100
        combined_score = min(combined_score, 100)
        
        # Determine overall risk level
        if combined_score >= 60:
            risk_level = "High"
        elif combined_score >= 30:
            risk_level = "Medium"
        elif combined_score > 0:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
            risk_factors.append("No obvious phishing indicators detected")
        
        return {
            "risk_score": combined_score,
            "text_score": text_score,
            "url_score": url_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "suspicious_urls": suspicious_urls
        }
    
    def analyze_url_internal(self, url):
        """Analyze a URL for phishing indicators (comprehensive version)."""
        risk_score = 0
        reasons = []
        
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Parse the URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if domain is valid and can be parsed
            if not domain:
                return 40, "Missing or invalid domain"
            
            # Extract domain without port
            if ':' in domain:
                domain_clean = domain.split(':')[0]
            else:
                domain_clean = domain
            
            # Check for suspicious domains
            for sus_domain in self.suspicious_domains:
                if sus_domain in domain_clean:
                    risk_score += 40
                    reasons.append(f"Domain similar to known phishing site: {sus_domain}")
            
            # Check for IP address instead of domain name
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_clean):
                risk_score += 30
                reasons.append(f"Uses IP address ({domain_clean}) instead of domain name")
            
            # Enhanced suspicious TLD detection
            suspicious_tlds = [
                '.tk', '.top', '.xyz', '.online', '.site', '.cf', '.ga', '.ml', '.gq', 
                '.info', '.biz', '.cc', '.pw', '.stream', '.zip', '.review', '.country',
                '.kim', '.cricket', '.science', '.work', '.party', '.gdn', '.click',
                '.loan', '.webcam', '.download', '.racing', '.accountant'
            ]
            
            # Get TLD
            domain_parts = domain_clean.split('.')
            if len(domain_parts) >= 2:
                tld = '.' + domain_parts[-1]
                if tld in suspicious_tlds:
                    risk_score += 20
                    reasons.append(f"Uses suspicious top-level domain: {tld}")
            
            # Enhanced brand protection - check for major services often targeted by phishers
            known_brands = [
                "paypal", "apple", "microsoft", "amazon", "google", "facebook", "instagram",
                "netflix", "bank", "credit", "coinbase", "binance", "blockchain", "wellsfargo",
                "chase", "citi", "amex", "bankofamerica", "capitalone", "venmo", "cashapp", 
                "zelle", "office365", "outlook", "icloud", "gmail", "yahoo", "spotify", "steam",
                "epic", "playstation", "xbox", "nintendo", "roblox", "discord", "twitch", "twitter",
                "linkedin", "dropbox", "onedrive", "zoom", "docusign", "fedex", "ups", "usps", "dhl",
                "adobe", "salesforce", "slack", "whatsapp", "telegram", "signal", "snapchat", "tiktok",
                "reddit", "pinterest", "tumblr", "wordpress", "shopify", "square", "stripe", "robinhood"
            ]
            
            # Check for subdomain abuse (e.g., paypal.secure-login.com)
            parts = domain.split('.')
            
            # If domain has multiple parts (potential subdomain structure)
            if len(parts) > 2:
                for brand in known_brands:
                    # Check for patterns like "paypal.phishing.com" or "paypal-secure.com"
                    if brand in parts[0] and brand not in parts[-2]:
                        risk_score += 35
                        reasons.append(f"Possible subdomain abuse with {brand}")
                        break
                    
                    # Check for obfuscation techniques like dots or dashes
                    if '-' in parts[0] and brand in parts[0]:
                        risk_score += 25
                        reasons.append(f"Suspicious domain with dashes containing {brand}")
                        break
            
            # Check for homograph attacks (lookalike characters)
            homograph_patterns = [
                (r'paypа', 'paypal'),  # Cyrillic 'а' instead of Latin 'a'
                (r'facеbook', 'facebook'),  # Cyrillic 'е' instead of Latin 'e'
                (r'аpple', 'apple'),  # Cyrillic 'а' instead of Latin 'a'
                (r'miсrosoft', 'microsoft'),  # Cyrillic 'с' instead of Latin 'c'
                (r'аmazon', 'amazon'),  # Cyrillic 'а' instead of Latin 'a'
                (r'gооgle', 'google'),  # Cyrillic 'о' instead of Latin 'o'
            ]
            
            for pattern, brand in homograph_patterns:
                if re.search(pattern, domain):
                    risk_score += 50
                    reasons.append(f"Possible homograph attack mimicking {brand}")
                    break
            
            # Check for typosquatting (common misspellings)
            common_domains = {
                "paypal": ["paypal.com", "paypal", "pay-pal"],
                "amazon": ["amazon.com", "amazon"],
                "microsoft": ["microsoft.com", "microsoft"],
                "apple": ["apple.com", "apple", "icloud"],
                "google": ["google.com", "google", "gmail"],
                "facebook": ["facebook.com", "facebook", "fb"],
                "netflix": ["netflix.com", "netflix"],
                "instagram": ["instagram.com", "instagram", "ig"],
                "twitter": ["twitter.com", "twitter", "x.com"],
            }
            
            for brand, variations in common_domains.items():
                # Check if domain contains the brand but is not the legitimate domain
                if any(variation in domain for variation in variations) and not domain.endswith(variations[0]):
                    # Look for small variations of legitimate domains
                    typos = [
                        brand + "l.com",  # Extra 'l'
                        brand + "-secure.com",  # Added security text
                        brand + "accounts.com",  # Added account text
                        brand + ".org",  # Wrong TLD
                        brand + ".net",  # Wrong TLD
                        brand + "s.com",  # Plural form
                        brand.replace('a', 'e') + ".com",  # Character substitution
                        brand.replace('e', 'a') + ".com",  # Character substitution
                        brand.replace('i', 'l') + ".com",  # Character substitution
                        brand.replace('o', '0') + ".com",  # Character substitution
                        brand + "-login.com",  # Added login text
                        brand.replace('u', 'w') + ".com",  # Character substitution
                    ]
                    
                    for typo in typos:
                        if typo in domain or domain.startswith(brand):
                            risk_score += 35
                            reasons.append(f"Possible typosquatting of {brand}")
                            break
            
            # Check for suspicious URL path or query patterns
            suspicious_paths = [
                "login", "signin", "account", "verify", "secure", "update", "confirm",
                "password", "authenticate", "auth", "validation", "wallet", "payment"
            ]
            
            path_lower = parsed.path.lower()
            
            if any(term in path_lower for term in suspicious_paths):
                # Check for deeper path analysis
                if re.search(r'/(login|signin|account)/(verify|confirm|secure|update)', path_lower):
                    risk_score += 20
                    reasons.append("Suspicious path pattern indicating phishing")
                else:
                    risk_score += 10
                    reasons.append("Path contains terms commonly used in phishing")
            
            # Check for URL parameters that might be suspicious
            query_lower = parsed.query.lower()
            suspicious_params = [
                "redirect", "url", "return", "next", "goto", "link", "target",
                "token", "auth", "session", "account", "email", "password", "credential"
            ]
            
            if any(param in query_lower for param in suspicious_params):
                if "login" in path_lower or "signin" in path_lower or "account" in path_lower:
                    risk_score += 20
                    reasons.append("Suspicious redirection parameters with authentication path")
                else:
                    risk_score += 10
                    reasons.append("Suspicious query parameters")
            
            # Check for HTTP instead of HTTPS
            if parsed.scheme != "https":
                risk_score += 15
                reasons.append("Not using secure HTTPS")
            
            # Check for unusual port numbers
            if ":" in domain:
                port = domain.split(":")[1]
                if port not in ["80", "443"]:
                    risk_score += 25
                    reasons.append(f"Unusual port number: {port}")
            
            # Return the analysis results
            reason_text = "; ".join(reasons) if reasons else "No specific issues found"
            return risk_score, reason_text
        except Exception:
            # Silent error handling without logging
            return 0, "Could not analyze URL"

# URL features transformer for the pipeline (only available if sklearn is available)
if SKLEARN_AVAILABLE:
    class URLFeaturesExtractor(BaseEstimator, TransformerMixin):
        def fit(self, x, y=None):
            return self
        
        def transform(self, data):
            if isinstance(data, tuple) and len(data) >= 2:
                try:
                    import pandas as pd
                    if isinstance(data[1], pd.DataFrame):
                        return data[1].values
                except ImportError:
                    pass
            # Return empty array with proper shape if no URL features
            return np.zeros((len(data), 1))

def main():
    """Main function to run the chatbot or train the model."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="PhishGuard AI - Advanced Phishing Detection")
    parser.add_argument("--train", action="store_true", help="Train the model instead of starting the chatbot")
    parser.add_argument("--use-csv", action="store_true", help="Use CSV dataset for training (if available)")
    parser.add_argument("--sample-size", type=int, default=10000, help="Number of samples to use from CSV dataset")
    parser.add_argument("--no-csv", action="store_true", help="Don't use CSV dataset even if available")
    
    args = parser.parse_args()
    
    # Get user's name with proper error handling
    print("Before we start, I'd like to personalize your experience.")
    try:
        user_name = input("What should I call you? ")
        user_name = user_name.strip() or "User"  # Default to "User" if empty
    except KeyboardInterrupt:
        print("\n\nSession terminated. Goodbye!")
        return
    except EOFError:
        print("\n\nInput stream closed. Using default name.")
        user_name = "User"
    
    # Initialize chatbot with user's name
    chatbot = PhishingDetectionChatbot(name=user_name)
    
    # Check if we're in training mode
    if args.train:
        print("\n" + "="*50)
        print(" PHISHGUARD AI MODEL TRAINING")
        print("="*50)
        
        # Determine whether to use CSV
        use_csv = args.use_csv or (not args.no_csv)
        
        print(f"\nTraining Configuration:")
        print(f"- Using CSV Dataset: {use_csv}")
        if use_csv:
            print(f"- Sample Size: {args.sample_size}")
        
        print("\nStarting training...\n")
        success = chatbot.train_model(use_csv=use_csv, sample_size=args.sample_size)
        
        if success:
            print("\n" + "="*50)
            print(" MODEL TRAINING COMPLETED SUCCESSFULLY")
            print("="*50)
            print("\nThe model has been saved and is ready for use.")
        else:
            print("\n" + "="*50)
            print(" MODEL TRAINING FAILED")
            print("="*50)
            print("\nPlease check the error messages above and try again.")
    else:
        # Normal chatbot mode
        # Banner already printed at program start
        print(f"Hello {user_name}, I'm here to help you identify phishing attempts and learn about cybersecurity.")
        print("Type 'exit' to quit.\n")
        
        while True:
            try:
                user_input = input(f"{user_name}: ")
                
                if user_input.lower() in ["exit", "quit", "bye"]:
                    print(f"\nChatbot: Stay safe online, {user_name}! Goodbye!")
                    break
                    
                response = chatbot.generate_response(user_input)
                print(f"\nChatbot: {response}\n")
                
            except KeyboardInterrupt:
                print("\nChatbot: Session terminated. Stay safe online!")
                break
            except Exception as e:
                print(f"\nChatbot: I encountered an error: {str(e)}. Let's continue.")


if __name__ == "__main__":
    main()
