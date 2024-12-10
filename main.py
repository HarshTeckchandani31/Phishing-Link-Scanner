 import sys
from scanner.url_validator import validate_url
from scanner.security_checker import SecurityChecker
from scanner.report_generator import generate_report

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    
    # Validate URL format
    if not validate_url(url):
        print("Error: Invalid URL format")
        sys.exit(1)

    # Initialize security checker
    checker = SecurityChecker()
    
    # Perform security checks
    results = checker.analyze_url(url)
    
    # Generate and display report
    report = generate_report(url, results)
    print(report)

if __name__ == "__main__":
    main()