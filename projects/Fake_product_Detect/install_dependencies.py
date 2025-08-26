#!/usr/bin/env python3
"""
Dependency Installation Script for ScamShield
Installs dependencies one by one with error handling
"""

import subprocess
import sys

def install_package(package_name):
    """Install a single package with error handling"""
    try:
        print(f"Installing {package_name}...")
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', package_name], 
                              capture_output=True, text=True, check=True)
        print(f"✓ {package_name} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {package_name}")
        print(f"Error: {e.stderr}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error installing {package_name}: {e}")
        return False

def main():
    print("ScamShield - Dependency Installation")
    print("====================================\n")
    
    # Core dependencies (required)
    core_packages = [
        'Flask',
        'Werkzeug', 
        'Jinja2',
        'MarkupSafe',
        'itsdangerous',
        'click',
        'blinker'
    ]
    
    # Optional dependencies (for enhanced features)
    optional_packages = [
        'requests',
        'beautifulsoup4',
        'lxml',
        'certifi',
        'urllib3'
    ]
    
    # ML dependencies (may fail on some systems)
    ml_packages = [
        'numpy',
        'scikit-learn', 
        'joblib',
        'transformers',
        'torch',
        'torchvision',
        'tensorflow-cpu',
        'textblob'
    ]
    
    # DNS/Network dependencies
    network_packages = [
        'dnspython',
        'python-whois'
    ]
    
    print("Installing core Flask dependencies...")
    core_success = 0
    for package in core_packages:
        if install_package(package):
            core_success += 1
    
    print(f"\nCore packages: {core_success}/{len(core_packages)} installed")
    
    if core_success < len(core_packages):
        print("Warning: Some core packages failed to install. The application may not work properly.")
    
    print("\nInstalling optional web scraping dependencies...")
    optional_success = 0
    for package in optional_packages:
        if install_package(package):
            optional_success += 1
    
    print(f"\nOptional packages: {optional_success}/{len(optional_packages)} installed")
    
    print("\nInstalling ML dependencies (may take time)...")
    ml_success = 0
    for package in ml_packages:
        if install_package(package):
            ml_success += 1
    
    print(f"\nML packages: {ml_success}/{len(ml_packages)} installed")
    
    print("\nInstalling network analysis dependencies...")
    network_success = 0
    for package in network_packages:
        if install_package(package):
            network_success += 1
    
    print(f"\nNetwork packages: {network_success}/{len(network_packages)} installed")
    
    print("\n" + "="*50)
    print("INSTALLATION SUMMARY:")
    print(f"Core Flask: {core_success}/{len(core_packages)} ({'✓' if core_success == len(core_packages) else '⚠️'})")
    print(f"Web Scraping: {optional_success}/{len(optional_packages)} ({'✓' if optional_success > 0 else '✗'})")
    print(f"Machine Learning: {ml_success}/{len(ml_packages)} ({'✓' if ml_success > 0 else '✗'})")
    
    if ml_success > 0:
        print("\nNote: Advanced ML libraries are available for better detection accuracy.")
        print("This includes Hugging Face Transformers for NLP-based analysis.")
    print(f"Network Analysis: {network_success}/{len(network_packages)} ({'✓' if network_success > 0 else '✗'})")
    
    print("\n" + "="*50)
    
    if core_success == len(core_packages):
        print("✓ Ready to run! Use: python app_simple.py")
    else:
        print("⚠️  Some core dependencies missing. Try running with just Flask:")
        print("   pip install Flask")
        print("   python app_simple.py")
    
    print("\nNote: The application will work with partial dependencies.")
    print("Missing features will be automatically disabled.")

if __name__ == '__main__':
    main()

