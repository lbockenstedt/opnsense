"""Process entry point for the OPNsense firewall spoke.

Self-heals missing Python dependencies, configures logging, then runs an
OpnControlPlane that connects to the Lab Manager Hub and hosts the OpnSpoke
module that drives the OPNsense REST API.
"""
# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
# Stdlib os under a private alias, used only by the dependency self-heal below.
import os as _os
# Wrap the whole self-heal in a try so any failure in it can never stop startup.
try:
    # Prefer the package-style import (repo checkout); fall back to a flat import
    # when the spoke is installed with core/src copied next to it.
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    # Point the guard at this spoke's requirements.txt (one directory above src/).
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    # Self-heal is best-effort: if it fails the real imports below will report the problem.
    pass

# Standard-library logging for status and error messages.
import logging
# argparse reads the --id/--secret/--hub command-line options.
import argparse
# asyncio runs the control plane's event loop.
import asyncio
# os reads the HUB_URL environment variable.
import os
# Type hints for the config dictionary.
from typing import Dict, Any
# Base class providing the Hub websocket connection and command routing;
# try the repo layout first, then the flat installed layout.
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
# The OPNsense module that does the firewall work.
from opn_spoke import OpnSpoke

# Shared logging configuration: try the flat install path, then the repo path.
try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        # Neither copy of logging_setup is available: define a minimal stand-in so the
        # spoke still logs with the same format.
        import logging as _logging
        # Same line format / date format as the shared logging_setup module.
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            """Fallback logging setup: console (and optional file) output at the given level."""
            # Log to file + console when a log file is given; None lets basicConfig use stderr.
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            # force=True replaces any handlers a library may already have installed.
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# Configure root logging at boot. Previously this entrypoint called no
# basicConfig at all -> root defaulted to WARNING and ALL INFO logs (API
# request INFO, sync progress) were silently dropped at cold start.
configure_logging()
# Named logger so control-plane messages can be filtered separately.
logger = logging.getLogger("OpnControlPlane")

class OpnControlPlane(BaseControlPlane):
    """Control plane (Hub connection + module routing) for the OPNsense spoke."""
    def get_service_name(self) -> str:
        """Systemd service name the Hub restarts on self-update."""
        return "lm-opnsense"

    # NOTE: this string is not the class docstring (it follows a method); the real
    # docstring is at the top of the class.
    """
    Control Plane for the OPNsense module.
    Inherits core connectivity and routing from BaseControlPlane.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None, config: Dict[str, Any] = None):
        """Store the spoke config and connect to the Hub as module type "firewall"."""
        # Initialize attributes before calling super().__init__ to ensure that background 
        # workers (like updater_worker) started by the base class have access to required data.
        self.config = config or {}
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        # Advertise "firewall" so the Hub routes firewall commands to this spoke.
        self.module_type = "firewall"

    async def run_hub_mode(self):
        """Native LM Spoke behavior."""
        # Announce which Hub this spoke is connecting to.
        logger.info(f"Starting OPNsense Module in HUB MODE -> {self.hub_url}")

        # Integrate with Lab Manager's native spoke structure
        opn_spoke = OpnSpoke(self.spoke_id, self.config)
        self.register_module("opn", opn_spoke)

        # Delegate to BaseControlPlane's main loop
        await self.run()

# Script entry point: parse the command line and run the control plane.
if __name__ == "__main__":
    # Command-line options: spoke identity, auth secrets and the Hub URL.
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
    # Parse argv into an args namespace.
    args = parser.parse_args()

    # Build the control plane, then run it until it stops.
    cp = OpnControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    # Run the Hub loop; Ctrl+C exits quietly instead of printing a traceback.
    try:
        asyncio.run(cp.run_hub_mode())
    except KeyboardInterrupt:
        # Interactive stop: nothing to clean up.
        pass