# ScamShield - Troubleshooting Guide

This guide helps you resolve common issues when setting up and running ScamShield.

## Installation Issues

### Problem: pip install fails with "distutils" error
**Solution**: Use the automated installer instead:
```bash
python install_dependencies.py
```

This installer handles dependency conflicts gracefully and will report which features are available.

### Problem: NumPy or scikit-learn installation fails
**Solution**: The application works without ML libraries. They will be automatically disabled.

To install ML dependencies manually:
```bash
pip install numpy
pip install scikit-learn
pip install joblib
```

### Problem: Virtual environment activation fails
**Windows PowerShell**: 
```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```

**Windows Command Prompt**:
```bash
venv\Scripts\activate.bat
```

## Running Issues

### Problem: "Module not found" errors
**Solution**: 
1. Ensure you're in the virtual environment
2. Run the dependency checker:
```bash
python app_simple.py
```

This will show which modules are available and disable missing features automatically.

### Problem: Port 5000 already in use
**Solution**: Change the port in the application:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Use different port
```

### Problem: Web scraping not working
**Possible causes**:
- `requests` or `beautifulsoup4` not installed
- Target website blocks scraping
- Network connectivity issues

**Solution**: The application will work without web scraping, showing neutral scores for website analysis.

## Feature Availability Check

Visit `http://localhost:5000/status` to see which features are enabled:

```json
{
  "features": {
    "requests": true,
    "beautifulsoup": true,
    "ssl": true,
    "dns": true,
    "machine_learning": true
  }
}
```

## Performance Issues

### Problem: Analysis takes too long
**Solutions**:
1. Disable web scraping for faster analysis (remove URL)
2. Reduce timeout values in the code
3. Use `app_simple.py` instead of `app.py`

### Problem: High memory usage
**Solution**: Restart the application periodically or implement caching limits.

## Common Error Messages

### "SSL certificate verify failed"
**Solution**: This is handled automatically in the simplified version. Web scraping will use `verify=False`.

### "DNS resolution failed"
**Solution**: The application continues without DNS checking. Ensure internet connectivity for full features.

### "ML model initialization failed"
**Solution**: The application falls back to rule-based analysis. Install scikit-learn for ML features.

## Development Issues

### Problem: Changes not reflected
**Solution**: Flask debug mode should auto-reload. If not, restart manually:
```bash
Ctrl+C
python app_simple.py
```

### Problem: Template not found
**Solution**: Ensure the templates directory structure:
```
templates/
└── page.html
```

## Browser Issues

### Problem: Form submission fails
**Solution**: 
1. Check browser console for JavaScript errors
2. Ensure the Flask server is running
3. Try a different browser

### Problem: Styling looks broken
**Solution**: 
1. Check internet connection (Tailwind CSS loads from CDN)
2. Clear browser cache
3. Try incognito/private mode

## Getting Help

1. **Check the status endpoint**: `http://localhost:5000/status`
2. **Run with debug info**: Look at the console output when starting the app
3. **Minimal installation**: Try with just Flask if all else fails:
   ```bash
   pip install Flask
   python app_simple.py
   ```

## Emergency Minimal Setup

If nothing works, create a minimal version:

```python
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return "<h1>ScamShield is running!</h1><p>Minimal setup successful.</p>"

if __name__ == '__main__':
    app.run(debug=True)
```

Save as `test.py` and run with `python test.py`.

## Contact

If you're still experiencing issues:
1. Note your Python version: `python --version`
2. Note your operating system
3. Copy the full error message
4. List which dependencies installed successfully

The application is designed to work with partial dependencies, so most issues should not prevent basic functionality.

