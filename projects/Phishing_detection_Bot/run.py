#!/usr/bin/env python3
"""
PhishGuard AI - Launcher Script

This script provides an easy way to run the PhishGuard AI application
with automatic dependency checking and installation.
"""

import sys
import subprocess
import os
import time

def check_and_install_dependencies():
    """
    Check if required dependencies are installed and install them if missing.
    """
    print("Checking dependencies...")
    
    required_packages = [
        'flask',
        'flask-cors',
        'requests',
        'nltk',
        'scikit-learn',
        'numpy',
        'pandas'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✓ {package} is installed")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package} is missing")
    
    if missing_packages:
        print(f"\nInstalling missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("✓ All dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("✗ Failed to install dependencies. Please install manually:")
            print(f"pip install {' '.join(missing_packages)}")
            return False
    else:
        print("✓ All dependencies are already installed")
    
    return True

def download_nltk_data():
    """
    Download required NLTK data.
    """
    try:
        import nltk
        print("Downloading NLTK data...")
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        print("✓ NLTK data downloaded")
    except Exception as e:
        print(f"Warning: Could not download NLTK data: {e}")

def run_web_app():
    """
    Run the Flask web application.
    """
    print("\n" + "="*60)
    print("  PHISHGUARD AI - ADVANCED PHISHING DETECTION")
    print("="*60)
    print("\nStarting web application...")
    print("The application will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server\n")
    
    try:
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\nServer stopped. Thank you for using PhishGuard AI!")
    except Exception as e:
        print(f"Error starting application: {e}")
        print("\nTrying alternative startup method...")
        
        # Alternative: run via subprocess
        try:
            subprocess.run([sys.executable, 'app.py'])
        except Exception as e2:
            print(f"Alternative method also failed: {e2}")
            print("\nPlease check your installation and try running 'python app.py' manually.")

def run_console_mode():
    """
    Run the console-based chatbot.
    """
    print("\nStarting console mode...\n")
    try:
        import subprocess
        subprocess.run([sys.executable, 'phishguard-ai.py'])
    except Exception as e:
        print(f"Error starting console mode: {e}")

def main():
    """
    Main launcher function.
    """
    print("PhishGuard AI Launcher")
    print("=" * 40)
    
    # Check and install dependencies
    if not check_and_install_dependencies():
        print("\nDependency installation failed. Exiting.")
        return
    
    # Download NLTK data
    download_nltk_data()
    
    # Ask user for preferred mode
    print("\nChoose how to run PhishGuard AI:")
    print("1. Web Application (Recommended) - Interactive web interface")
    print("2. Console Mode - Command-line chatbot")
    print("3. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                run_web_app()
                break
            elif choice == '2':
                run_console_mode()
                break
            elif choice == '3':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()

