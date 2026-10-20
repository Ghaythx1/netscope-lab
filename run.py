"""
NetScope Lab — Application entry point.

Usage:
    python run.py
"""

import os
from netscope_lab.app import create_app

if __name__ == "__main__":
    config_name = os.environ.get("NETSCOPE_ENV", "development")
    app = create_app(config_name)
    print("\n" + "=" * 60)
    print("  [*] NetScope Lab is running!")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 60 + "\n")
    app.run(
        host="127.0.0.1",
        port=5000,
        # Keep the interactive debugger off, especially when run with sudo.
        debug=False,
        use_reloader=False,
    )
