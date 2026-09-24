class WhitelistEngine:
    def __init__(self):
        self.trusted_domains = [
            "presidencyuniversity.in",
            "google.com",
            "github.com",
            "microsoft.com"
        ]

    def is_whitelisted(self, url: str) -> bool:
        for domain in self.trusted_domains:
            if domain in url:
                return True
        return False