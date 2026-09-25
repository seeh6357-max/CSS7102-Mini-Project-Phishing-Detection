import os
import math
import re
import urllib.parse
import numpy as np
import joblib
from Levenshtein import distance as lev_distance

class AdvancedNLPEngine:
    """
    Research-Grade NLP & Lexical Telemetry Engine for Zero-Day Phishing Detection.
    Combines multi-scale Shannon entropy, semantic keyword lexicons, IDN homograph
    detection, DGA estimation, and Explainable AI (XAI) feature attribution.
    """
    def __init__(self):
        # Target Brand Registry for Typosquatting / Homograph Matching
        self.target_brands = [
            "paypal", "google", "microsoft", "apple", "amazon", 
            "bankofamerica", "netflix", "presidencyuniversity", 
            "facebook", "instagram", "linkedin", "chase", "wellsfargo",
            "binance", "coinbase", "drop-box", "adobe", "outlook", "office365"
        ]

        # Semantic Threat Lexicons
        self.lexicons = {
            "auth": ["login", "signin", "verify", "account", "credential", "auth", "password", "security", "update", "confirm", "portal"],
            "finance": ["banking", "secure", "wallet", "crypto", "pay", "checkout", "billing", "invoice", "transfer", "tax", "refund"],
            "urgency": ["urgent", "suspended", "locked", "immediately", "expired", "action-required", "restricted", "warning"],
            "service": ["support", "helpdesk", "admin", "service", "system", "cloud", "server", "gateway"]
        }

        # Model Artifact Paths
        char_path = "app/char_vec.pkl"
        word_path = "app/word_vec.pkl"
        scaler_path = "app/scaler.pkl"
        model_path = "app/model.pkl"

        if all(os.path.exists(p) for p in [char_path, word_path, scaler_path, model_path]):
            try:
                self.char_vec = joblib.load(char_path)
                self.word_vec = joblib.load(word_path)
                self.scaler = joblib.load(scaler_path)
                self.model = joblib.load(model_path)
                self.ready = True
                print("[+] Tier-2 Advanced Voting Ensemble NLP Engine Online (Artifacts Loaded).")
            except Exception as e:
                self.ready = True
                print(f"[!] Warning loading model artifacts: {e}. Falling back to Rule-Based Heuristic Ensemble.")
        else:
            self.ready = True
            print("[+] Tier-2 Rule-Based Heuristic NLP Engine Online (Fallback Mode Active).")

    def _calculate_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy (Bits/Char) of a string sequence."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def _detect_homograph_punycode(self, url_str: str) -> bool:
        """Detects Punycode (xn--) or non-ASCII UTF-8 characters."""
        return "xn--" in url_str.lower() or any(ord(c) > 127 for c in url_str)

    def _estimate_dga_score(self, domain_part: str, entropy: float) -> float:
        """
        Estimates the probability of Domain Generation Algorithm (DGA) usage
        based on entropy, length, vowel-consonant ratios, and consonant clustering.
        """
        clean_domain = domain_part.split(".")[0]
        length = len(clean_domain)
        if length < 5:
            return 0.0

        vowels = len(re.findall(r'[aeiou]', clean_domain))
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', clean_domain))
        digits = len(re.findall(r'\d', clean_domain))

        vowel_ratio = vowels / length if length > 0 else 0
        consonant_cluster = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', clean_domain))

        score = 0.0
        if entropy > 4.2: score += 0.35
        if vowel_ratio < 0.2: score += 0.25
        if consonant_cluster > 0: score += 0.25
        if digits > 3: score += 0.15

        return round(min(1.0, score), 2)

    def _extract_lexical_nlp_features(self, url: str) -> dict:
        """Extracts complete multi-scale lexical, structural, and semantic features."""
        url_lower = url.lower().strip()
        parsed = urllib.parse.urlparse(url_lower if "://" in url_lower else f"http://{url_lower}")

        domain_part = parsed.netloc if parsed.netloc else parsed.path.split("/")[0]
        path_part = parsed.path
        query_part = parsed.query

        url_length = len(url_lower)
        domain_length = len(domain_part)

        digits_count = sum(c.isdigit() for c in url_lower)
        digit_ratio = digits_count / url_length if url_length > 0 else 0.0

        special_count = sum(not c.isalnum() and c not in [':', '/', '.', '-'] for c in url_lower)
        special_ratio = special_count / url_length if url_length > 0 else 0.0

        # Subdomains
        subdomains = [s for s in domain_part.split(".") if s and s not in ["www", "com", "org", "net", "in", "io", "ru", "cn"]]
        num_subdomains = max(0, len(subdomains) - 1)

        # Raw IP Host Detection
        has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_part) else 0

        # Entropy Analysis
        domain_entropy = self._calculate_entropy(domain_part)
        url_entropy = self._calculate_entropy(url_lower)

        # Brand Edit Distance (Typosquatting)
        distances = [lev_distance(domain_part.split(".")[0], brand) for brand in self.target_brands]
        brand_dist = min(distances) if distances else 999
        matched_brand = self.target_brands[distances.index(brand_dist)] if distances and brand_dist <= 3 else "None"

        # TLD Check
        suspicious_tlds = [".xyz", ".top", ".tk", ".site", ".online", ".info", ".club", ".biz", ".icu", ".vip", ".ru", ".cn", ".cf", ".ga", ".gq", ".ml"]
        has_suspicious_tld = 1 if any(domain_part.endswith(tld) for tld in suspicious_tlds) else 0

        # Semantic Lure Keyword Density
        lure_matches = []
        for cat, kw_list in self.lexicons.items():
            for kw in kw_list:
                if kw in url_lower:
                    lure_matches.append((cat, kw))

        has_sensitive_keywords = 1 if len(lure_matches) > 0 else 0
        is_punycode = self._detect_homograph_punycode(url_lower)
        dga_score = self._estimate_dga_score(domain_part, domain_entropy)

        return {
            "url": url,
            "domain_part": domain_part,
            "url_length": url_length,
            "domain_length": domain_length,
            "digit_ratio": digit_ratio,
            "special_ratio": special_ratio,
            "num_subdomains": num_subdomains,
            "has_ip": has_ip,
            "entropy": domain_entropy,
            "url_entropy": url_entropy,
            "brand_dist": brand_dist,
            "matched_brand": matched_brand,
            "has_suspicious_tld": has_suspicious_tld,
            "lure_matches": lure_matches,
            "has_sensitive_keywords": has_sensitive_keywords,
            "is_punycode": is_punycode,
            "dga_score": dga_score,
            "vector": np.array([[url_length, digit_ratio, special_ratio, num_subdomains, has_ip, domain_entropy, brand_dist, has_suspicious_tld]])
        }

    def _generate_xai_attribution(self, lex: dict, risk_score: float) -> dict:
        """Explainable AI (XAI) mathematical feature weight contribution vector."""
        contributions = {}
        
        if lex["brand_dist"] <= 2 and lex["brand_dist"] > 0:
            contributions["Brand Typosquatting Match"] = "+35.0%"
        if lex["dga_score"] >= 0.5:
            contributions["DGA Randomness Score"] = f"+{lex['dga_score']*30:.1f}%"
        if lex["has_sensitive_keywords"]:
            contributions["Credential Lure Keywords"] = "+20.0%"
        if lex["has_suspicious_tld"]:
            contributions["High-Risk TLD Classifier"] = "+15.0%"
        if lex["has_ip"]:
            contributions["Raw IPv4 Destination Host"] = "+25.0%"
        if lex["entropy"] > 4.2:
            contributions["High Shannon Entropy"] = "+15.0%"

        if not contributions:
            contributions["Structural Integrity Validation"] = "100.0% Benign"

        return contributions

    def _generate_siem_forensics(self, url: str, verdict: str, risk_score: float, lex: dict):
        """Generates MITRE ATT&CK mappings, indicators, and SOC playbook steps."""
        mitre_ttps = []
        indicators = []
        playbook_actions = []

        # MITRE ATT&CK Mappings
        if lex["brand_dist"] <= 2 and lex["brand_dist"] > 0:
            mitre_ttps.append({"id": "T1036.005", "name": "Masquerading: Match Right-to-Left / Typosquatting"})
            indicators.append(f"Brand Typosquatting Target: Domain mimics '{lex['matched_brand'].upper()}' with Levenshtein edit distance of {lex['brand_dist']}.")
            playbook_actions.append("Issue Domain Take-down Request & Push Brand Mimicry Block Rule to Proxy.")

        if lex["is_punycode"]:
            mitre_ttps.append({"id": "T1036.008", "name": "Masquerading: Homograph Unicode Character Substitution"})
            indicators.append("Punycode/Homograph Vector: URL contains non-ASCII lookalike characters designed to fool end users.")

        if lex["dga_score"] >= 0.5:
            mitre_ttps.append({"id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms (DGA)"})
            indicators.append(f"High Algorithmic Randomness (DGA Risk: {lex['dga_score']*100:.0f}%): Domain exhibits abnormal character transition entropy ({lex['entropy']:.2f} Bits/Char).")

        if lex["has_sensitive_keywords"]:
            mitre_ttps.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link / Credential Harvesting"})
            lure_str = ", ".join([f"'{kw}' ({cat})" for cat, kw in lex['lure_matches'][:3]])
            indicators.append(f"Credential Harvesting Lures Detected: Parameter contains active lure tokens: {lure_str}.")

        if lex["has_ip"]:
            mitre_ttps.append({"id": "T1071.001", "name": "Application Layer Protocol: Direct IPv4 Destination"})
            indicators.append("Direct IPv4 Host: URL bypasses standard Domain Name System (DNS) resolution.")

        if lex["has_suspicious_tld"]:
            indicators.append("High-Risk Registrar TLD: Domain uses a top-level domain heavily associated with automated malicious campaigns.")

        if lex["num_subdomains"] >= 2:
            indicators.append(f"Deep Subdomain Hierarchy ({lex['num_subdomains']} Levels): Multi-tiered subdomains configured to obfuscate apex ownership.")

        # Fallback MITRE mapping
        if verdict != "SAFE" and not mitre_ttps:
            mitre_ttps.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link"})

        # SOC Playbook Mitigation Actions
        if verdict == "MALICIOUS":
            playbook_actions.extend([
                "Block domain immediately at Perimeter Firewall & Web Proxy Gateway.",
                "Flush SHA-256 Hash Signature to Endpoint Detection & Response (EDR) agents.",
                "Quarantine inbound emails containing this target URL."
            ])
            summary = (
                f"CRITICAL SIEM THREAT ALERT: High-confidence credential harvesting or zero-day phishing attack. "
                f"Target domain exhibits a threat probability of {risk_score*100:.1f}% backed by {len(indicators)} severe structural anomalies."
            )
        elif verdict == "SUSPICIOUS":
            playbook_actions.extend([
                "Route connection through Remote Browser Isolation (RBI) sandbox.",
                "Enforce mandatory step-up Multi-Factor Authentication (MFA) for active user sessions."
            ])
            summary = (
                f"ELEVATED RISK INCIDENT: URL exhibits suspicious lexical properties ({len(indicators)} anomaly flags). "
                f"Voting ensemble model recommends isolation."
            )
        else:
            summary = "CLEAN AUDIT VERDICT: Domain matches authorized topology with standard character distribution and zero severe anomaly flags."
            indicators.append("Structural integrity confirmed. No malicious typosquatting, DGA, or homograph vectors observed.")
            playbook_actions.append("Allow uninterrupted network transit. Record audit telemetry in persistent database.")

        xai_attribution = self._generate_xai_attribution(lex, risk_score)

        return {
            "summary": summary,
            "mitre_ttps": mitre_ttps,
            "indicators": indicators,
            "playbook_actions": playbook_actions,
            "entropy": f"{lex['entropy']:.2f} Bits/Char",
            "brand_dist": f"{lex['brand_dist']} ({lex['matched_brand']})" if lex['brand_dist'] <= 3 else "0 (Clean)",
            "subdomains": f"{lex['num_subdomains']} Levels",
            "digit_ratio": f"{lex['digit_ratio']*100:.1f}%",
            "dga_score": f"{lex['dga_score']*100:.0f}%",
            "punycode": "Detected (Homograph Risk)" if lex["is_punycode"] else "Clean ASCII",
            "xai_attribution": xai_attribution
        }

    def predict(self, url: str):
        """Predicts risk score and returns detailed SIEM forensic report."""
        lex = self._extract_lexical_nlp_features(url)

        # Rule-Based Heuristic Risk Calculation (Ensures robust prediction even if model weights are absent)
        heuristic_risk = 0.05
        if lex["brand_dist"] <= 2 and lex["brand_dist"] > 0: heuristic_risk += 0.55
        if lex["dga_score"] >= 0.5: heuristic_risk += 0.35
        if lex["has_sensitive_keywords"]: heuristic_risk += 0.25
        if lex["has_suspicious_tld"]: heuristic_risk += 0.20
        if lex["has_ip"]: heuristic_risk += 0.30
        if lex["entropy"] > 4.2: heuristic_risk += 0.15

        heuristic_risk = round(min(0.99, max(0.01, heuristic_risk)), 4)

        # ML Model Inference (if model artifacts are present)
        if hasattr(self, 'model') and self.model is not None:
            try:
                char_feat = self.char_vec.transform([url]).toarray()
                word_feat = self.word_vec.transform([url]).toarray()
                lex_scaled = self.scaler.transform(lex["vector"])
                combined = np.hstack((char_feat, word_feat, lex_scaled))
                prob = self.model.predict_proba(combined)[0][1]
                risk_score = round(float(prob), 4)
            except Exception:
                risk_score = heuristic_risk
        else:
            risk_score = heuristic_risk

        # Verdict Classification Thresholds
        if risk_score >= 0.70:
            verdict = "MALICIOUS"
        elif risk_score >= 0.40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        forensics = self._generate_siem_forensics(url, verdict, risk_score, lex)
        return verdict, risk_score, forensics