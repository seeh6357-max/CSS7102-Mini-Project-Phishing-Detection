from urllib.parse import urlparse

class EnterpriseWhitelistGatekeeper:
    def __init__(self):
        self.whitelisted_domains = {
            "presidencyuniversity.in",
            "google.com",
            "github.com",
            "microsoft.com",
            "wikipedia.org",
            "amazon.com",
            "python.org",
            "stackoverflow.com"
        }

    def is_whitelisted(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
            domain = domain.split(":")[0]
            
            if domain in self.whitelisted_domains:
                return True
                
            for trusted in self.whitelisted_domains:
                if domain.endswith("." + trusted):
                    return True
            return False
        except Exception:
            return False
