import logging
import argparse
import asyncio
from typing import Dict, Any
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
from opn_spoke import OpnSpoke

logger = logging.getLogger("OpnControlPlane")

class OpnControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-opnsense"

    """
    Control Plane for the OPNsense module.
    Inherits core connectivity and routing from BaseControlPlane.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None, config: Dict[str, Any] = None):
        # Initialize attributes before calling super().__init__ to ensure that background 
        # workers (like updater_worker) started by the base class have access to required data.
        self.config = config or {}
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "firewall"

    async def run_hub_mode(self):
        """Native LM Spoke behavior."""
        logger.info(f"Starting OPNsense Module in HUB MODE -> {self.hub_url}")

        # Integrate with Lab Manager's native spoke structure
        opn_spoke = OpnSpoke(self.spoke_id, self.config)
        self.register_module("opn", opn_spoke)

        # Delegate to BaseControlPlane's main loop
        await self.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", nargs='?', const="lm-secret", default="lm-secret", help="Authentication secret (default: lm-secret)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", required=True, help="Hub WebSocket URL")
    args = parser.parse_args()

    cp = OpnControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    try:
        asyncio.run(cp.run_hub_mode())
    except KeyboardInterrupt:
        pass