# ScamShield - Advanced AI/ML Fake Product Detection System

ScamShield is an advanced AI/ML-powered web application that helps users detect counterfeit and fake products in e-commerce. The system uses multiple detection methods including machine learning, rule-based analysis, web scraping, and online URL analysis to provide comprehensive authenticity scoring and detailed analysis.

## Features

### 🤖 AI/ML Detection Methods
- **Machine Learning Classification**: Trained Naive Bayes model for text analysis
- **Advanced Rule-Based Engine**: Multi-weighted scoring system
- **Real-time Web Scraping**: Live website content analysis
- **Domain Security Analysis**: SSL certificate and DNS validation
- **Price Anomaly Detection**: Market comparison algorithms

### 🔍 Analysis Components
- **Price Analysis (25% weight)**: Brand-specific market value comparison
- **Domain Analysis (25% weight)**: SSL, DNS, domain structure validation
- **Content Analysis (20% weight)**: Weighted keyword detection
- **ML Prediction (20% weight)**: TF-IDF + Naive Bayes classification
- **Web Scraping (10% weight)**: Trust indicators and suspicious patterns

### 🌐 Online URL Analysis
- **Real-time Website Scraping**: Live content analysis
- **Trust Indicator Detection**: SSL, privacy policies, contact info
- **Suspicious Pattern Recognition**: Scam website characteristics
- **Domain Reputation Checking**: Known seller verification

### 🛡️ Security & Privacy
- **No Image Storage**: Text-based analysis only
- **Secure Processing**: All analysis done server-side
- **Privacy-First**: No personal data collection
- **Report System**: Community-driven fake product reporting

## Technology Stack

### Backend
- **Python Flask**: Web framework
- **scikit-learn**: Machine learning algorithms
- **NumPy**: Numerical computing
- **Beautiful Soup**: Web scraping
- **Requests**: HTTP library for web analysis
- **DNSPython**: DNS resolution
- **python-whois**: Domain information

### Frontend
- **HTML5/CSS3/JavaScript**: Modern web technologies
- **Tailwind CSS**: Utility-first styling
- **Font Awesome**: Professional icons
- **Responsive Design**: Mobile-optimized interface

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Setup Instructions

1. **Clone or download the project to your local machine**

2. **Navigate to the project directory**:
   ```bash
   cd Fake_product_Detect
   ```

3. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   ```

4. **Activate the virtual environment**:
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

5. **Install dependencies using the automated installer**:
   ```bash
   python install_dependencies.py
   ```
   
   Or manually install with pip:
   ```bash
   pip install -r requirements.txt
   ```
   
   **Note**: If you encounter installation errors, the automated installer will handle them gracefully and the application will still work with partial dependencies.

## Running the Application

1. **Start the Flask server**:
   ```bash
   python app_simple.py
   ```
   
   Or use the original advanced version (if all dependencies are installed):
   ```bash
   python app.py
   ```

2. **Open your web browser** and navigate to:
   ```
   http://localhost:5000
   ```

3. **The application will be running** and ready to use!

## Usage

### Analyzing a Product

1. **Fill in the product form**:
   - **Product Name**: Enter the product name/title
   - **Price**: Enter the product price in USD
   - **Website URL**: Paste the product page URL (optional)
   - **Description**: Add product description (optional)
   - **Image**: Upload a product image (optional)

2. **Click "Analyze Product"** to start the analysis

3. **View the results**:
   - Authenticity score (0-100%)
   - Detailed analysis breakdown
   - Specific recommendations
   - Option to report fake products

### Understanding the Analysis

The system evaluates products based on:

- **Price Analysis**: Compares price against known market values
- **Seller Verification**: Checks if the seller/domain is legitimate
- **Description Analysis**: Looks for suspicious keywords
- **URL Analysis**: Examines URL structure for red flags

### Authenticity Scores

- **80-100%**: Likely authentic - proceed with caution
- **60-79%**: Needs further research - verify additional details
- **0-59%**: High risk - avoid purchase

## File Structure

```
Fake_product_Detect/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/
│   └── page.html         # Main HTML template
└── template/             # Original template directory
    └── page.html         # Original HTML file
```

## API Endpoints

### POST /analyze
Analyzes a product for authenticity.

**Parameters**:
- `product_name` (string, required): Product name
- `price` (number, required): Product price
- `url` (string, optional): Product page URL
- `description` (string, optional): Product description
- `image` (file, optional): Product image

**Response**:
```json
{
  "success": true,
  "result": {
    "authenticity_score": 85.5,
    "is_authentic": true,
    "analysis_details": [...],
    "recommendation": {...}
  }
}
```

### POST /report
Reports a fake product.

**Parameters**:
- `product_name` (string): Product name
- `price` (string): Product price
- `url` (string): Product URL

## Customization

### Adding New Brands
Edit the `brand_price_ranges` dictionary in `app.py`:

```python
self.brand_price_ranges = {
    'your_brand': {'min': 50, 'max': 500},
    # ... existing brands
}
```

### Adding Legitimate Sellers
Update the `legitimate_sellers` set in `app.py`:

```python
self.legitimate_sellers = {
    'your-trusted-site.com',
    # ... existing sellers
}
```

### Modifying Suspicious Keywords
Update the `suspicious_keywords` set in `app.py`:

```python
self.suspicious_keywords = {
    'your_suspicious_word',
    # ... existing keywords
}
```

## Security Considerations

- File uploads are limited to 16MB
- Only image files are accepted for upload
- Uploaded files are stored securely with hashed names
- Input validation is performed on all form data
- No personal data is stored permanently

## Future Enhancements

- Machine learning integration for image analysis
- Database integration for persistent storage
- User authentication and history tracking
- Advanced image processing for logo detection
- Integration with e-commerce APIs
- Browser extension development
- Mobile app version

## Contributing

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues, questions, or suggestions:
- Check the code comments for detailed explanations
- Review the browser console for any JavaScript errors
- Ensure all dependencies are properly installed
- Verify that the Flask server is running on the correct port

## License

This project is for educational and demonstration purposes. Please ensure compliance with relevant laws and regulations when detecting counterfeit products.

---

**Note**: This is a demonstration system. While it provides useful analysis, it should not be the sole factor in determining product authenticity. Always use multiple verification methods when making important purchases.

