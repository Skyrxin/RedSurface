#!/usr/bin/env python3
"""
RedSurface - Attack Surface Intelligence Graph Generator

A modular Python CLI tool for external reconnaissance that discovers assets,
fingerprints technologies, and generates an interactive Attack Surface Graph.
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import List, Tuple

from utils.logger import setup_logger, get_logger
from utils.output import ensure_output_dir
from core.target import Target
from core.graph_engine import AttackSurfaceGraph
from modules.discovery import InfrastructureDiscoverer, DiscoveredAsset
from modules.fingerprint import TechFingerprinter, TechFingerprint
from modules.osint import OSINTCollector, OSINTResults


# ASCII Banner
BANNER = r"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ███████╗██████╗ ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗ ║
║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝ ║
║   ██████╔╝█████╗  ██║  ██║███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗   ║
║   ██╔══██╗██╔══╝  ██║  ██║╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝   ║
║   ██║  ██║███████╗██████╔╝███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗ ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝ ║
║                                                                           ║
║              Attack Surface Intelligence Graph Generator                  ║
║                              v1.0.0                                       ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="redsurface",
        description="Attack Surface Intelligence Graph Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com
  python main.py --target example.com --output ./results
  python main.py --target example.com --verbose
        """,
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target domain to perform reconnaissance on (e.g., example.com)",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./output",
        help="Output directory for results (default: ./output)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )

    parser.add_argument(
        "--hunter-key",
        type=str,
        default=None,
        help="Hunter.io API key for email discovery (optional)",
    )

    parser.add_argument(
        "--github-token",
        type=str,
        default=None,
        help="GitHub personal access token for higher API rate limits (optional)",
    )

    parser.add_argument(
        "--hibp-key",
        type=str,
        default=None,
        help="Have I Been Pwned API key for breach data (optional)",
    )

    parser.add_argument(
        "--generate-permutations",
        action="store_true",
        help="Generate email permutations from discovered names",
    )

    parser.add_argument(
        "--verify-emails",
        action="store_true",
        help="Verify discovered emails via emailrep.io (rate limited)",
    )

    parser.add_argument(
        "--skip-osint",
        action="store_true",
        help="Skip OSINT collection phase",
    )

    parser.add_argument(
        "--nvd-key",
        type=str,
        default=None,
        help="NVD API key for increased CVE lookup rate limits (optional)",
    )

    parser.add_argument(
        "--no-nvd",
        action="store_true",
        help="Disable NVD CVE lookups (use mock database only)",
    )

    parser.add_argument(
        "--no-content-analysis",
        action="store_true",
        help="Skip HTML/JS content analysis during fingerprinting",
    )

    parser.add_argument(
        "--use-system-dns",
        action="store_true",
        help="Use system default DNS instead of public DNS servers (8.8.8.8, 1.1.1.1)",
    )

    return parser.parse_args()


async def phase_discovery(
    target: Target,
    discoverer: InfrastructureDiscoverer,
) -> List[DiscoveredAsset]:
    """
    Phase 1-2: Infrastructure discovery - subdomain enumeration and DNS resolution.

    Args:
        target: Target instance to populate
        discoverer: InfrastructureDiscoverer instance

    Returns:
        List of discovered assets
    """
    logger = get_logger()
    logger.info("[Phase 1-2] Infrastructure discovery (subdomains + DNS)...")

    try:
        assets = await discoverer.run(target.domain)

        # Populate target with discovered data
        for asset in assets:
            # Add subdomain if not root domain
            if asset.hostname != target.domain:
                target.add_subdomain(asset.hostname)

            # Add IP mappings
            for ip in asset.ips:
                target.add_ip(asset.hostname, ip)

            # Add cloud service mappings
            for ip in asset.ips:
                for provider in asset.cloud_providers:
                    target.add_cloud_service(ip, provider)

        logger.info(
            f"Discovery complete: {len(assets)} assets, "
            f"{len(target.subdomains)} subdomains, "
            f"{len(target.ips)} hosts resolved"
        )
        return assets

    except Exception as e:
        logger.error(f"Discovery phase failed: {e}")
        return []


async def phase_fingerprinting(
    target: Target,
    fingerprinter: TechFingerprinter,
    hostnames: List[str],
    analyze_content: bool = True,
) -> Tuple[int, int]:
    """
    Phase 3-4: Technology fingerprinting and vulnerability mapping.

    Args:
        target: Target instance to populate
        fingerprinter: TechFingerprinter instance
        hostnames: List of hostnames to fingerprint
        analyze_content: Whether to analyze HTML/JS content

    Returns:
        Tuple of (tech_count, vuln_count)
    """
    logger = get_logger()
    logger.info("[Phase 3-4] Technology fingerprinting & vulnerability mapping...")

    if not hostnames:
        logger.warning("No hostnames to fingerprint")
        return 0, 0

    try:
        results = await fingerprinter.run(hostnames, analyze_content=analyze_content)
        
        # Extract technologies and WAFs from results
        fingerprint_results = results.get("technologies", {})
        waf_results = results.get("wafs", {})

        # Populate target with fingerprint data
        for hostname, fingerprints in fingerprint_results.items():
            for fp in fingerprints:
                tech_name = f"{fp.name} {fp.version}" if fp.version else fp.name
                target.add_technology(hostname, tech_name)

                # Add CVE mappings
                for cve in fp.cves:
                    target.add_vulnerability(tech_name, cve["cve_id"])
        
        # Add WAF detections as technologies
        for hostname, waf_name in waf_results.items():
            target.add_technology(hostname, f"WAF: {waf_name}")

        tech_count = sum(len(techs) for techs in target.technologies.values())
        vuln_count = sum(len(cves) for cves in target.vulnerabilities.values())
        
        if waf_results:
            logger.info(f"WAFs detected: {', '.join(set(waf_results.values()))}")

        logger.info(
            f"Fingerprinting complete: {tech_count} technologies, "
            f"{vuln_count} potential vulnerabilities"
        )
        return tech_count, vuln_count

    except Exception as e:
        logger.error(f"Fingerprinting phase failed: {e}")
        return 0, 0


async def phase_osint(
    target: Target,
    osint_collector: OSINTCollector,
    hunter_key: str | None = None,
    hibp_key: str | None = None,
    generate_permutations: bool = False,
    verify_emails: bool = False,
) -> OSINTResults:
    """
    Phase 5: OSINT collection - emails and employee discovery.

    Args:
        target: Target instance to populate
        osint_collector: OSINTCollector instance
        hunter_key: Optional Hunter.io API key
        hibp_key: Optional Have I Been Pwned API key
        generate_permutations: Generate email permutations from names
        verify_emails: Verify discovered emails

    Returns:
        OSINTResults with collected data
    """
    logger = get_logger()
    logger.info("[Phase 5] OSINT collection (emails & people)...")

    try:
        results = await osint_collector.run(
            target.domain,
            hunter_key=hunter_key,
            hibp_key=hibp_key,
            generate_permutations=generate_permutations,
            verify_emails=verify_emails,
        )

        # Populate target with OSINT data
        for email in results.emails:
            target.add_email(email)

        for person in results.people:
            target.add_person(person.to_dict())

        # Log additional info
        sources_count = len(results.sources_queried)
        verified_count = len(results.verified_emails)
        
        logger.info(
            f"OSINT complete: {len(results.emails)} emails, "
            f"{len(results.people)} people from {sources_count} sources"
        )
        
        if results.dns_hints.get("mail_provider"):
            logger.info(f"Mail provider detected: {results.dns_hints['mail_provider']}")
        
        if verified_count > 0:
            logger.info(f"Verified {verified_count} emails via emailrep.io")
        
        return results

    except Exception as e:
        logger.error(f"OSINT phase failed: {e}")
        return OSINTResults()


def phase_graph_building(target: Target) -> AttackSurfaceGraph:
    """
    Phase 6: Build the Attack Surface Intelligence Graph.

    Args:
        target: Populated Target instance

    Returns:
        AttackSurfaceGraph with all nodes and edges
    """
    logger = get_logger()
    logger.info("[Phase 6] Building Attack Surface Intelligence Graph...")

    attack_graph = AttackSurfaceGraph(title=f"Attack Surface: {target.domain}")
    attack_graph.build_from_target(target)

    logger.info(
        f"Graph complete: {attack_graph.node_count} nodes, "
        f"{attack_graph.edge_count} edges"
    )
    return attack_graph


def phase_export(
    target: Target,
    attack_graph: AttackSurfaceGraph,
    output_dir: Path,
) -> None:
    """
    Phase 7: Export all results to files.

    Args:
        target: Populated Target instance
        attack_graph: Built AttackSurfaceGraph
        output_dir: Output directory path
    """
    logger = get_logger()
    logger.info("[Phase 7] Exporting results...")

    safe_domain = target.domain.replace(".", "_")

    # Export scan results JSON
    results_path = output_dir / f"{safe_domain}_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(target.to_dict(), f, indent=2, default=str)
    logger.info(f"Scan results: {results_path}")

    # Export interactive HTML graph
    html_path = output_dir / f"{safe_domain}_graph.html"
    attack_graph.export_html(str(html_path))

    # Export graph data JSON
    graph_json_path = output_dir / f"{safe_domain}_graph.json"
    attack_graph.export_json(str(graph_json_path))

    logger.info(f"All results saved to: {output_dir}")


async def run_reconnaissance(
    target: Target,
    output_dir: Path,
    hunter_key: str | None = None,
    github_token: str | None = None,
    hibp_key: str | None = None,
    generate_permutations: bool = False,
    verify_emails: bool = False,
    skip_osint: bool = False,
    nvd_key: str | None = None,
    use_nvd: bool = True,
    analyze_content: bool = True,
    use_system_dns: bool = False,
) -> AttackSurfaceGraph:
    """
    Main reconnaissance orchestration function.
    Coordinates all phases with proper async/await data flow.

    Args:
        target: Target instance to populate
        output_dir: Directory for output files
        hunter_key: Optional Hunter.io API key for OSINT
        github_token: Optional GitHub token for OSINT
        hibp_key: Optional Have I Been Pwned API key
        generate_permutations: Generate email permutations
        verify_emails: Verify discovered emails
        skip_osint: Skip OSINT collection phase
        nvd_key: Optional NVD API key for CVE lookups
        use_nvd: Whether to use real NVD API
        analyze_content: Whether to analyze HTML/JS content
        use_system_dns: Use system default DNS instead of public DNS

    Returns:
        Populated AttackSurfaceGraph instance
    """
    logger = get_logger()

    logger.info(f"{'=' * 60}")
    logger.info(f"Starting reconnaissance on: {target.domain}")
    logger.info(f"{'=' * 60}")
    target.start_scan()

    # Initialize modules
    discoverer = InfrastructureDiscoverer(
        timeout=3.0,
        max_concurrent=50,
        use_system_dns=use_system_dns,
    )
    fingerprinter = TechFingerprinter(
        timeout=10.0,
        max_concurrent=20,
        verify_ssl=False,
        nvd_api_key=nvd_key,
        use_nvd=use_nvd,
    )
    osint_collector = OSINTCollector(
        timeout=15.0,
        github_token=github_token,
    )

    # Phase 1-2: Infrastructure Discovery (async)
    assets = await phase_discovery(target, discoverer)

    # Phase 3-4: Technology Fingerprinting (async)
    # Pass discovered hostnames to fingerprinter
    hostnames_to_scan = [target.domain] + list(target.subdomains)
    await phase_fingerprinting(target, fingerprinter, hostnames_to_scan, analyze_content=analyze_content)

    # Phase 5: OSINT Collection (async)
    if not skip_osint:
        await phase_osint(
            target,
            osint_collector,
            hunter_key=hunter_key,
            hibp_key=hibp_key,
            generate_permutations=generate_permutations,
            verify_emails=verify_emails,
        )
    else:
        logger.info("[Phase 5] OSINT collection skipped (--skip-osint)")

    # Mark scan complete
    target.end_scan()
    logger.info(f"{'=' * 60}")
    logger.info(f"Reconnaissance completed in {target.scan_duration:.2f} seconds")
    logger.info(f"{'=' * 60}")

    # Phase 6: Build Graph (sync - NetworkX operations)
    attack_graph = phase_graph_building(target)

    # Phase 7: Export Results (sync - file I/O)
    phase_export(target, attack_graph, output_dir)

    return attack_graph


def main() -> int:
    """
    Main entry point for RedSurface.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    args = parse_arguments()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    output_path = Path(args.output)
    log_file = output_path / "redsurface.log"

    logger = setup_logger(level=log_level, log_file=log_file)

    # Display banner
    if not args.no_banner:
        print(BANNER)

    # Ensure output directory exists
    try:
        output_dir = ensure_output_dir(output_path)
        logger.debug(f"Output directory: {output_dir}")
    except PermissionError:
        logger.error(f"Permission denied: Cannot create output directory '{args.output}'")
        return 1

    # Initialize target
    target = Target(domain=args.target)
    logger.info(f"Target initialized: {target.domain}")

    # Run the async reconnaissance pipeline
    try:
        attack_graph = asyncio.run(
            run_reconnaissance(
                target=target,
                output_dir=output_dir,
                hunter_key=args.hunter_key,
                github_token=args.github_token,
                hibp_key=args.hibp_key,
                generate_permutations=args.generate_permutations,
                verify_emails=args.verify_emails,
                skip_osint=args.skip_osint,
                nvd_key=args.nvd_key,
                use_nvd=not args.no_nvd,
                analyze_content=not args.no_content_analysis,
                use_system_dns=args.use_system_dns,
            )
        )
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Fatal error during reconnaissance: {e}")
        return 1

    # Print summary
    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Target:          {target.domain}")
    print(f"  Subdomains:      {len(target.subdomains)}")
    print(f"  IPs Resolved:    {len(target.ips)}")
    print(f"  Technologies:    {sum(len(t) for t in target.technologies.values())}")
    print(f"  Vulnerabilities: {sum(len(v) for v in target.vulnerabilities.values())}")
    print(f"  Emails Found:    {len(target.emails)}")
    print(f"  People Found:    {len(target.people)}")
    print(f"  Graph Nodes:     {attack_graph.node_count}")
    print(f"  Graph Edges:     {attack_graph.edge_count}")
    print(f"  Scan Duration:   {target.scan_duration:.2f}s")
    print("=" * 60)
    print(f"  Output:          {output_dir}")
    print("=" * 60 + "\n")

    logger.info("RedSurface completed successfully ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
