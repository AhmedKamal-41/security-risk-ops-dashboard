"""
Vulnerability scoring logic.
"""

# Scoring weights and constants
CVSS_WEIGHT = 0.4
KEV_BONUS = 2.0
EPSS_WEIGHT = 5.0
AGE_WEIGHT_PER_DAY = 0.01
MAX_AGE_DAYS_CAP = 365


def compute_risk_score(cvss_score, is_kev, epss_score, age_days):
    """
    Compute risk score for a vulnerability based on multiple factors.
    
    The risk score combines:
    - CVSS score (0-10 scale) weighted by CVSS_WEIGHT
    - KEV bonus added if vulnerability is in Known Exploited Vulnerabilities
    - EPSS score (0-1 scale) weighted by EPSS_WEIGHT
    - Age factor (age_days) weighted by AGE_WEIGHT_PER_DAY (capped at MAX_AGE_DAYS_CAP)
    
    Args:
        cvss_score: CVSS score (0-10), can be None or Decimal
        is_kev: Boolean indicating if vulnerability is in KEV, can be None
        epss_score: EPSS score (0-1), can be None or Decimal
        age_days: Age of vulnerability in days, can be None or int
        
    Returns:
        float: Computed risk score
    """
    # Handle None values safely and convert Decimal to float
    from decimal import Decimal
    
    if cvss_score is None:
        cvss = 0.0
    elif isinstance(cvss_score, Decimal):
        cvss = float(cvss_score)
    else:
        cvss = float(cvss_score)
    
    kev = bool(is_kev) if is_kev is not None else False
    
    if epss_score is None:
        epss = 0.0
    elif isinstance(epss_score, Decimal):
        epss = float(epss_score)
    else:
        epss = float(epss_score)
    
    if age_days is None:
        age = 0
    else:
        age = int(age_days)
    
    # Cap age at MAX_AGE_DAYS_CAP if provided
    if MAX_AGE_DAYS_CAP is not None and age > MAX_AGE_DAYS_CAP:
        age = MAX_AGE_DAYS_CAP
    
    # Calculate components
    cvss_component = cvss * CVSS_WEIGHT
    kev_component = KEV_BONUS if kev else 0.0
    epss_component = epss * EPSS_WEIGHT
    age_component = age * AGE_WEIGHT_PER_DAY
    
    # Sum all components
    risk_score = cvss_component + kev_component + epss_component + age_component
    
    return float(risk_score)
    """
    Compute risk score for a vulnerability based on multiple factors.
    
    The risk score combines:
    - CVSS score (0-10 scale) weighted by CVSS_WEIGHT
    - KEV bonus added if vulnerability is in Known Exploited Vulnerabilities
    - EPSS score (0-1 scale) weighted by EPSS_WEIGHT
    - Age factor (age_days) weighted by AGE_WEIGHT_PER_DAY (capped at MAX_AGE_DAYS_CAP)
    
    Args:
        cvss_score: CVSS score (0-10), can be None
        is_kev: Boolean indicating if vulnerability is in KEV, can be None
        epss_score: EPSS score (0-1), can be None
        age_days: Age of vulnerability in days, can be None
        
    Returns:
        float: Computed risk score
        
    Example:
        >>> compute_risk_score(cvss_score=7.5, is_kev=True, epss_score=0.8, age_days=30)
        9.3
        # Calculation:
        # CVSS component: 7.5 * 0.4 = 3.0
        # KEV bonus: 2.0
        # EPSS component: 0.8 * 5.0 = 4.0
        # Age component: 30 * 0.01 = 0.3
        # Total: 3.0 + 2.0 + 4.0 + 0.3 = 9.3
    """
    # Handle None values safely
    cvss = cvss_score if cvss_score is not None else 0.0
    kev = bool(is_kev) if is_kev is not None else False
    epss = epss_score if epss_score is not None else 0.0
    age = age_days if age_days is not None else 0
    
    # Cap age at MAX_AGE_DAYS_CAP if provided
    if MAX_AGE_DAYS_CAP is not None and age > MAX_AGE_DAYS_CAP:
        age = MAX_AGE_DAYS_CAP
    
    # Calculate components
    cvss_component = cvss * CVSS_WEIGHT
    kev_component = KEV_BONUS if kev else 0.0
    epss_component = epss * EPSS_WEIGHT
    age_component = age * AGE_WEIGHT_PER_DAY
    
    # Sum all components
    risk_score = cvss_component + kev_component + epss_component + age_component
    
    return float(risk_score)
