import logging
import argparse
import asyncio
import os
from typing import Dict, Any
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
from opn_spoke import OpnSpoke

try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# Configure root logging at boot. Previously this entrypoint called no
# basicConfig at all -> root defaulted to WARNING and ALL INFO logs (API
# request INFO, sync progress) were silently dropped at cold start.
configure_logging()
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
    # --hub is NOT required: omit it (or pass 'auto'/empty) and BaseControlPlane
    # auto-discovers the hub (DNS lm-hub.<suffix> then mDNS) on each connect.
    # Default to the HUB_URL env (installer writes HUB_URL=auto) so an empty/
    # unset value becomes the auto-discovery sentinel instead of an argparse
    # crash. The old ws://localhost:8765 default is broken now that the hub's
    # bare 8765 listener was retired by the unified-:443 merge.
    parser.add_argument("--hub", default=os.getenv("HUB_URL") or "auto",
                        help="Hub WebSocket URL (or 'auto' to discover; default auto)")
    args = parser.parse_args()

    cp = OpnControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    try:
        asyncio.run(cp.run_hub_mode())
    except KeyboardInterrupt:
        pass