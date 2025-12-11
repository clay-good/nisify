"""
Demo data generator for Nisify.

Provides sample data generation for quick demos and evaluation
without requiring actual platform credentials.

Usage:
    from nisify.demo import generate_demo_data

    # Generate sample evidence and maturity data
    generate_demo_data()

    # Then start dashboard to see results
    nisify dashboard
"""

from nisify.demo.generator import (
    DemoGenerator,
    DemoProfile,
    generate_demo_data,
)

__all__ = [
    "DemoGenerator",
    "DemoProfile",
    "generate_demo_data",
]
