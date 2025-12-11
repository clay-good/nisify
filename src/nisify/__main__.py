"""
Entry point for running Nisify as a module.

Usage:
    python -m nisify [command] [options]

This allows Nisify to be executed directly as a Python module,
which is useful for development and testing without installing
the package.
"""

from nisify.cli import main

if __name__ == "__main__":
    main()
