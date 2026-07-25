#!/usr/bin/env python3
"""
OSINT Intelligence Framework — Main Entry Point.

Usage:
    python -m osint_framework.main --target example.com --modules cybint
    python -m osint_framework.main --target johndoe --modules socmint
    python -m osint_framework.main --target email@domain.com --modules all
"""

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from osint_framework.config.settings import load_config
from osint_framework.core.engine import OSINTEngine
from osint_framework.core.reporting import OSINTReporter


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cerberus AI — OSINT Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target company.com --modules cybint
  %(prog)s --target username --modules socmint
  %(prog)s --target email@domain.com --modules all
  %(prog)s --target company.com --modules all --output report.json
        """,
    )

    parser.add_argument(
        "--target", type=str, required=True,
        help="Target (domain, username, email)",
    )
    parser.add_argument(
        "--modules", type=str, default="all",
        choices=["all", "socmint", "cybint", "darkweb"],
        help="Module type to execute",
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Output file path",
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Configuration file path",
    )
    parser.add_argument(
        "--format", type=str, default="json",
        choices=["json", "html"], help="Output format",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Initialize engine
    print("  Cerberus AI — OSINT Intelligence Framework")
    print("=" * 50)

    engine = OSINTEngine(config)
    await engine.initialize()

    # plugin_manager is guaranteed to exist after initialize()
    assert engine.plugin_manager is not None

    # List loaded plugins
    plugins = engine.plugin_manager.list_plugins()
    print(f"\n Loaded {len(plugins)} plugins:")
    for p in plugins:
        status = "" if p["enabled"] else ""
        print(f"  {status} {p['name']} ({p['category']})")

    # Determine modules
    modules = None if args.modules == "all" else [args.modules]

    # Run intelligence cycle
    print(f"\n Target: {args.target}")
    print(f" Modules: {args.modules}")
    print("\n Gathering intelligence...\n")

    report = await engine.run_intelligence_cycle(args.target, modules)

    # Generate output
    reporter = OSINTReporter()

    if args.format == "json":
        output = reporter.generate_json_report(report)
    else:
        output = reporter.generate_html_report(report)

    # Save or print
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')  # noqa: UP017
    output_file = args.output or f"osint_report_{timestamp}.{args.format}"
    with open(output_file, "w") as f:
        f.write(output)

    # Print summary
    summary = reporter.generate_summary(report)
    print("\n" + "=" * 50)
    print(" INTELLIGENCE SUMMARY")
    print("=" * 50)
    print(f"  Report ID:        {summary['report_id']}")
    print(f"  Target:           {summary['target']}")
    print(f"  Entities Found:   {summary['entities_discovered']}")
    print(f"  Relationships:    {summary['relationships_found']}")
    # summary values are object, but we know these are strings/numbers
    risk_level = str(summary["risk_level"]).upper()  # type: ignore[call-overload]
    print(f"  Risk Level:       {risk_level}")
    print(f"  Risk Score:       {summary['risk_score']:.2f}")
    print(f"  Confidence:       {summary['confidence_level']:.0%}")
    print(f"  Total Findings:   {summary['total_findings']}")
    print("\n  Categories:")
    categories = summary.get("categories", {})
    if isinstance(categories, dict):
        for cat, count in categories.items():
            print(f"    {cat}: {count}")
    print(f"\n Report saved to: {output_file}")

    await engine.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
