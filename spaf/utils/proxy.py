import os
import random
from typing import Optional, List
from spaf.utils.logger import logger

class ProxyManager:
    def __init__(self):
        self.proxy_file = os.getenv("PROXY_FILE")
        self.proxies = self._load_proxies()
        self.use_tor = os.getenv("USE_TOR", "false").lower() == "true"
        self.tor_proxy = os.getenv("TOR_PROXY", "socks5://127.0.0.1:9050")

    def _load_proxies(self) -> List[str]:
        if self.proxy_file and os.path.exists(self.proxy_file):
            with open(self.proxy_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def get_proxy(self) -> Optional[str]:
        if self.use_tor:
            return self.tor_proxy
        if self.proxies:
            return random.choice(self.proxies)
        return None

    def get_user_agent(self) -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
        return random.choice(user_agents)

    async def test_proxy(self, proxy: str) -> bool:
        """Tests if a proxy is functional."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get("http://httpbin.org/ip", proxy=proxy, timeout=5) as resp:
                    return resp.status == 200
        except Exception:
            return False

proxy_manager = ProxyManager()
