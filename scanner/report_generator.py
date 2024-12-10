def generate_report(url, results):
    """
    Generates a formatted security report based on analysis results.
    """
    report = []
    report.append("\n=== Phishing URL Scanner Report ===")
    report.append(f"\nAnalyzed URL: {url}")
    
    # Suspicious Keywords
    report.append("\n[1] Suspicious Keywords Check:")
    keywords = results['suspicious_keywords']
    if keywords:
        report.append(f"⚠️  Found {len(keywords)} suspicious keywords: {', '.join(keywords)}")
    else:
        report.append("✅ No suspicious keywords found")
    
    # Protocol Check
    report.append("\n[2] Protocol Security Check:")
    protocol_info = results['protocol_check']
    if protocol_info['secure']:
        report.append("✅ Secure HTTPS protocol")
    else:
        report.append(f"⚠️  Insecure protocol: {protocol_info['protocol']}")
    
    # Domain Analysis
    report.append("\n[3] Domain Analysis:")
    domain_info = results['domain_analysis']
    report.append(f"Domain: {domain_info['domain']}")
    if domain_info['subdomain_count'] > 2:
        report.append(f"⚠️  Excessive subdomains: {domain_info['subdomain_count']}")
    if domain_info['contains_suspicious_tld']:
        report.append("⚠️  Suspicious top-level domain detected")
    if domain_info['length'] > 50:
        report.append("⚠️  Unusually long domain name")
    
    # Suspicious Patterns
    report.append("\n[4] Suspicious Patterns Check:")
    patterns = results['suspicious_patterns']
    found_patterns = [pattern for pattern, found in patterns.items() if found]
    if found_patterns:
        for pattern in found_patterns:
            report.append(f"⚠️  Found suspicious pattern: {pattern}")
    else:
        report.append("✅ No suspicious patterns detected")
    
    # Overall Risk Assessment
    risk_score = _calculate_risk_score(results)
    report.append(f"\nRisk Assessment: {risk_score}/10")
    report.append(_get_risk_recommendation(risk_score))
    
    return "\n".join(report)

def _calculate_risk_score(results):
    """Calculate a risk score from 0-10 based on analysis results."""
    score = 0
    
    # Add points for suspicious keywords
    score += min(len(results['suspicious_keywords']) * 2, 4)
    
    # Add points for insecure protocol
    if not results['protocol_check']['secure']:
        score += 2
    
    # Add points for domain analysis
    domain_info = results['domain_analysis']
    if domain_info['subdomain_count'] > 2:
        score += 1
    if domain_info['contains_suspicious_tld']:
        score += 2
    if domain_info['length'] > 50:
        score += 1
    
    # Add points for suspicious patterns
    patterns = results['suspicious_patterns']
    score += sum(1 for found in patterns.values() if found)
    
    return min(score, 10)

def _get_risk_recommendation(score):
    """Get a recommendation based on the risk score."""
    if score >= 7:
        return "🔴 HIGH RISK - Strong indicators of a phishing attempt. Avoid this URL!"
    elif score >= 4:
        return "🟡 MEDIUM RISK - Proceed with caution. Verify the source independently."
    else:
        return "🟢 LOW RISK - URL appears relatively safe, but always be vigilant."