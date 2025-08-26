"""
Training data for the phishing detection model.

This file contains sample datasets of phishing and legitimate messages
for training the machine learning model used in PhishGuard AI.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Sample phishing messages (based on real-world phishing attempts, with modifications)
phishing_samples = [
    "URGENT: Your account has been compromised. Click here to verify your identity: http://security-paypal.com/verify",
    "Dear Customer, We've detected suspicious activity on your account. Please verify your identity by providing your password and credit card details.",
    "Your Amazon account has been locked due to unusual activity. Click here to restore access: http://amazon-secure.tk/login",
    "Congratulations! You've won a $1000 gift card. To claim your prize, click here: http://free-gifts.xyz/claim",
    "Your PayPal account will be suspended. Please verify your information at: http://paypal-secure-login.com",
    "ALERT: Unusual activity detected on your account. Please confirm your identity by replying with your account password.",
    "Your bank account shows an unauthorized transaction of $750. To dispute this charge, provide your account details here: http://bank-verify.site",
    "Apple ID Alert: Your Apple ID has been locked for security reasons. Restore access here: http://apple-id-verify.ml",
    "Netflix: Your subscription has expired. Update your payment information here to continue watching: http://netflix-renew.info",
    "URGENT: Your tax refund of $3,459 is pending. Submit your bank details here to claim: http://tax-refund-irs.com",
    "Microsoft Security Alert: Your email account will be terminated. Verify your password here: http://outlook-security.online",
    "We've noticed unusual sign in activities in your account. Verify it's you by confirming your password and phone number.",
    "Your UPS package #37842 is waiting for delivery address confirmation. Confirm now: http://package-delivery-confirmation.net",
    "Your Facebook account was logged into from a new device. If this wasn't you, reset your password here: http://facebook-securitycheck.tk",
    "FINAL WARNING: Your account will be suspended within 24 hours. Verify your identity at: http://account-verification.co",
    "Your credit card statement shows a charge of $499. If you did not make this purchase, please reply with your card details to dispute.",
    "Your order #58742 has been processed. Track your shipment here: http://tracking-shipment.info/order",
    "Security Alert: Your Google account was accessed from a new location. Verify it was you: http://google-secure-login.site",
    "Important: Your document has been shared via DocuSign. Review and sign here: http://docusign-document.co",
    "Your parcel is on hold due to unpaid customs fee of $2.99. Pay online: http://delivery-customs-fee.com"
]

# Sample legitimate messages
legitimate_samples = [
    "Hi John, just checking if we're still on for lunch tomorrow at noon? Looking forward to catching up!",
    "Thank you for your recent purchase. Your order #12345 has been shipped and will arrive in 2-3 business days.",
    "Your monthly bank statement is now available. Please log in to your online banking portal to view it.",
    "Reminder: Your appointment with Dr. Smith is scheduled for Monday, Oct 15 at 3:00 PM. Please call if you need to reschedule.",
    "Hello team, please find attached the agenda for tomorrow's meeting. Let me know if you have any questions.",
    "Your password was successfully changed. If you did not make this change, please contact our support team.",
    "Thank you for signing up for our newsletter. You'll receive weekly updates on Fridays.",
    "Your flight to London has been confirmed. Check-in will be available 24 hours before departure.",
    "Dear Ms. Johnson, thank you for your inquiry. We have reviewed your application and would like to schedule an interview.",
    "Your subscription will renew automatically on Nov 12, 2025. If you wish to cancel, please visit your account settings.",
    "The document you requested is attached to this email. Please let me know if you need anything else.",
    "Your recent payment of $49.99 has been processed. Thank you for your business.",
    "Hi Sarah, I've shared the project files with you via Google Drive. You should receive access shortly.",
    "Reminder: The office will be closed on Monday for the holiday. Have a great long weekend!",
    "Your order has been delivered to the front porch as requested. Thank you for shopping with us.",
    "Your account password was recently reset. If you didn't request this change, please secure your account immediately.",
    "Thank you for your feedback on our service. We appreciate your input and will use it to improve.",
    "This is a reminder that your rent payment is due on the 1st of the month. Thank you for your prompt payment.",
    "The results of your recent lab tests are now available in your patient portal. Please log in to view them.",
    "Your insurance policy is up for renewal next month. No action is required as it will renew automatically."
]

# Sample URLs for model training
phishing_urls = [
    "http://paypa1.com/secure",
    "http://apple-id-verify.com/login",
    "http://secure-bankofamerica.com/verify",
    "http://ebay-motors-payment.com/transaction",
    "http://amazon-account-verify.com/login",
    "http://netflix-account-update.com/billing",
    "http://secure-payment-gateway.tk/process",
    "http://google-docs-share.ml/document",
    "http://microsoft365-login.xyz/verify",
    "http://fedex-tracking-shipment.info/track"
]

legitimate_urls = [
    "https://www.paypal.com/login",
    "https://appleid.apple.com/",
    "https://www.bankofamerica.com/online-banking/sign-in",
    "https://www.ebay.com/sh/ord/?orderid=123456",
    "https://www.amazon.com/gp/css/order-history",
    "https://www.netflix.com/YourAccount",
    "https://checkout.stripe.com/pay/cs_test",
    "https://docs.google.com/document/d/1abc123",
    "https://login.microsoftonline.com/",
    "https://www.fedex.com/tracking/numbers"
]

# Combined training data
def load_csv_dataset(sample_size=None, test_size=0.2, random_state=42):
    """
    Load and process the phishing URL dataset from CSV.
    
    Args:
        sample_size: Number of rows to sample (None for all data)
        test_size: Proportion to use for testing/validation
        random_state: Random seed for reproducibility
        
    Returns:
        X_train_df: DataFrame with training features
        X_test_df: DataFrame with testing features
        y_train: Training labels
        y_test: Testing labels
        feature_names: List of feature names
    """
    csv_path = "Dataset.csv"
    
    if not os.path.exists(csv_path):
        print(f"Warning: Dataset file {csv_path} not found.")
        return None, None, None, None, None
    
    print(f"Loading CSV dataset from {csv_path}...")
    
    try:
        # Load dataset
        df = pd.read_csv(csv_path)
        
        # Sample if requested
        if sample_size is not None and sample_size < len(df):
            df = df.sample(n=sample_size, random_state=random_state)
        
        print(f"Dataset loaded with {len(df)} samples")
        
        # Extract features and labels
        y = df['Type'].values  # 0 for legitimate, 1 for phishing
        
        # Drop the target column and any unnecessary columns
        drop_cols = ['Type']
        X_df = df.drop(columns=drop_cols)
        
        # Split into training and testing sets
        X_train_df, X_test_df, y_train, y_test = train_test_split(
            X_df, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Get feature names
        feature_names = X_df.columns.tolist()
        
        print(f"Data split into {len(X_train_df)} training and {len(X_test_df)} testing samples")
        
        return X_train_df, X_test_df, y_train, y_test, feature_names
        
    except Exception as e:
        print(f"Error loading CSV dataset: {e}")
        return None, None, None, None, None

def preprocess_url_features(X_df):
    """Preprocess the URL features from the dataset."""
    # Handle any missing values
    X_df = X_df.fillna(0)
    
    # Create a copy to avoid modifying the original
    X_processed = X_df.copy()
    
    # Scale numeric features using StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_processed)
    X_scaled_df = pd.DataFrame(X_scaled, columns=X_processed.columns)
    
    return X_scaled_df, scaler

def get_training_data(use_csv=True, sample_size=10000):
    """
    Get training data for the phishing detection model.
    
    Args:
        use_csv: Whether to use the CSV dataset
        sample_size: Number of rows to sample from CSV
        
    Returns:
        Different return values depending on source:
        - Text samples only: (text_samples, labels)
        - CSV only: (X_train_df, X_test_df, y_train, y_test, feature_names, scaler)
        - Both: ((text_train, text_test), (X_train_df, X_test_df), (y_train_text, y_test_text), 
                (y_train_csv, y_test_csv), feature_names, scaler)
    """
    # Text-based samples
    X_text = phishing_samples + legitimate_samples
    y_text = [1] * len(phishing_samples) + [0] * len(legitimate_samples)
    
    # Split text samples
    X_train_text, X_test_text, y_train_text, y_test_text = train_test_split(
        X_text, y_text, test_size=0.2, random_state=42
    )
    
    if not use_csv:
        return X_train_text, X_test_text, y_train_text, y_test_text
    
    # Try to load CSV data
    try:
        X_train_df, X_test_df, y_train_csv, y_test_csv, feature_names = load_csv_dataset(
            sample_size=sample_size
        )
        
        if X_train_df is None:
            print("Using only text-based samples for training.")
            return X_train_text, X_test_text, y_train_text, y_test_text
            
        # Preprocess URL features
        X_train_processed, scaler = preprocess_url_features(X_train_df)
        X_test_processed = pd.DataFrame(
            scaler.transform(X_test_df),
            columns=X_test_df.columns
        )
        
        return (
            (X_train_text, X_test_text),
            (X_train_processed, X_test_processed),
            (y_train_text, y_test_text),
            (y_train_csv, y_test_csv),
            feature_names,
            scaler
        )
        
    except Exception as e:
        print(f"Error preparing training data: {e}")
        print("Falling back to text-based samples only.")
        return X_train_text, X_test_text, y_train_text, y_test_text

# Validation data (for testing model performance)
def get_validation_data():
    """Get validation data for evaluating the phishing detection model."""
    phishing_validation = [
        "ALERT: Security breach detected! Reset your password immediately: http://secure-account-verify.net",
        "We've noticed suspicious login attempts on your account. Verify your identity: http://account-security-check.com",
        "Your package delivery failed. Please reschedule here: http://delivery-status-check.xyz",
        "You've received a secure document. Open here: http://docusign-secure.ml/view",
        "Your payment of $499 was declined. Update payment info: http://billing-update.site"
    ]
    
    legitimate_validation = [
        "Your monthly subscription has been processed successfully. Thank you for being a valued customer.",
        "Your support ticket #45678 has been received. A representative will contact you within 24 hours.",
        "The meeting scheduled for Thursday has been moved to Friday at the same time. Please update your calendar.",
        "Your recent order has shipped. Tracking number: TN87654321. Expected delivery: June 15.",
        "Thank you for registering for our webinar. It begins at 2pm EST tomorrow. Here's the link to join: https://zoom.us/j/123456789"
    ]
    
    X_val = phishing_validation + legitimate_validation
    y_val = [1] * len(phishing_validation) + [0] * len(legitimate_validation)
    return X_val, y_val

