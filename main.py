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
from core.config import ScanConfig, ScanMode
from core.graph_engine import AttackSurfaceGraph
from core.wizard import run_wizard
from modules.discovery import InfrastructureDiscoverer, DiscoveredAsset
from modules.fingerprint import TechFingerprinter, TechFingerprint
from modules.osint import OSINTCollector, OSINTResults
from modules.active_recon import ActiveRecon, ActiveReconResults
from modules.port_intel import PortIntel, PortIntelResults
from utils.report_generator import ReportGenerator


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
║                              v1.3.0                                       ║
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
  python main.py --input-file domains.txt --mode active
  python main.py --target example.com --exclude "dev.*,staging.*"
  python main.py --interactive
        """,
    )

    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target",
        type=str,
        help="Target domain to perform reconnaissance on (e.g., example.com)",
    )
    target_group.add_argument(
        "-i", "--input-file",
        type=str,
        help="File containing list of domains (one per line) for bulk scanning",
    )
    target_group.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive wizard for guided scan configuration",
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

    # Scan Mode and Scope
    parser.add_argument(
        "--mode",
        type=str,
        choices=["passive", "active"],
        default="passive",
        help="Scan mode: 'passive' (default) or 'active' (includes fuzzing)",
    )

    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="Comma-separated list of out-of-scope subdomains (e.g., 'dev.*,staging.target.com')",
    )

    # Custom Wordlists
    parser.add_argument(
        "--wordlist-subs",
        type=str,
        default=None,
        help="Custom path for subdomain enumeration wordlist",
    )

    parser.add_argument(
        "--wordlist-dirs",
        type=str,
        default=None,
        help="Custom path for directory fuzzing wordlist (active mode)",
    )

    # API Keys
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
        "--shodan-key",
        type=str,
        default=None,
        help="Shodan API key for port/service lookup (optional)",
    )

    parser.add_argument(
        "--nvd-key",
        type=str,
        default=None,
        help="NVD API key for increased CVE lookup rate limits (optional)",
    )

    # Feature Flags
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

    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML report generation (only output JSON and graph)",
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
            
            # Store full infrastructure asset details
            target.add_infrastructure_asset(asset.hostname, {
                "hostname": asset.hostname,
                "ips": asset.ips,
                "cnames": asset.cnames,
                "cloud_providers": asset.cloud_providers,
                "is_alive": asset.is_alive,
                "error": asset.error,
            })
            
            # Store SSL certificate info if available
            if asset.ssl_cert:
                target.add_ssl_certificate(asset.hostname, asset.ssl_cert.to_dict())
            
            # Store DNS records (A records from IPs, CNAME from cnames)
            if asset.ips:
                target.add_dns_records(asset.hostname, "A", asset.ips)
            if asset.cnames:
                target.add_dns_records(asset.hostname, "CNAME", asset.cnames)

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
        http_responses = results.get("responses", {})

        # Populate target with fingerprint data
        for hostname, fingerprints in fingerprint_results.items():
            for fp in fingerprints:
                tech_name = f"{fp.name} {fp.version}" if fp.version else fp.name
                target.add_technology(hostname, tech_name)
                
                # Store detailed technology info
                target.add_technology_detail(hostname, fp.to_dict())

                # Add CVE mappings
                for cve in fp.cves:
                    target.add_vulnerability(tech_name, cve["cve_id"])
        
        # Add WAF detections as technologies
        for hostname, waf_name in waf_results.items():
            target.add_technology(hostname, f"WAF: {waf_name}")
            target.add_technology_detail(hostname, {
                "name": waf_name,
                "version": None,
                "full_name": f"WAF: {waf_name}",
                "source": "header",
                "confidence": "high",
                "cves": [],
                "type": "waf",
            })
        
        # Store HTTP response details
        for hostname, response_data in http_responses.items():
            target.add_http_response(hostname, response_data)

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
    logger.info("[Phase 8] Building Attack Surface Intelligence Graph...")

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
    generate_report: bool = True,
) -> None:
    """
    Phase 7: Export all results to files.

    Args:
        target: Populated Target instance
        attack_graph: Built AttackSurfaceGraph
        output_dir: Output directory path
        generate_report: Whether to generate HTML report
    """
    logger = get_logger()
    logger.info("[Phase 9] Exporting results...")

    safe_domain = target.domain.replace(".", "_")

    # Export scan results JSON
    results_path = output_dir / f"{safe_domain}_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(target.to_dict(), f, indent=2, default=str)
    logger.info(f"Scan results: {results_path}")

    # Generate HTML report from results
    if generate_report:
        try:
            report_path = output_dir / f"{safe_domain}_report.html"
            report_gen = ReportGenerator(target.to_dict())
            html_report = report_gen.generate()
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            logger.info(f"HTML Report: {report_path}")
        except Exception as e:
            logger.warning(f"Failed to generate HTML report: {e}")

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
    use_system_dns: bool = True,  # Default to system DNS for better network compatibility
    scan_config: ScanConfig | None = None,
    generate_report: bool = True,
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
        scan_config: Optional ScanConfig for advanced settings
        generate_report: Whether to generate HTML report

    Returns:
        Populated AttackSurfaceGraph instance
    """
    logger = get_logger()
    
    # Use default config if not provided
    if scan_config is None:
        scan_config = ScanConfig(use_system_dns=use_system_dns)

    logger.info(f"{'=' * 60}")
    logger.info(f"Starting reconnaissance on: {target.domain}")
    logger.info(f"{'=' * 60}")
    target.start_scan()
    
    # Store scan configuration used
    target.set_scan_config(scan_config.to_dict())

    # Initialize modules with config
    discoverer = InfrastructureDiscoverer(
        timeout=scan_config.dns_timeout,
        max_concurrent=scan_config.max_concurrent,
        use_system_dns=scan_config.use_system_dns,
    )
    fingerprinter = TechFingerprinter(
        timeout=scan_config.http_timeout,
        max_concurrent=50,  # Higher concurrency for faster HTTP checks
        verify_ssl=False,
        nvd_api_key=nvd_key or scan_config.nvd_api_key,
        use_nvd=use_nvd and getattr(scan_config, 'module_vuln_lookup', True),
    )
    osint_collector = OSINTCollector(
        timeout=10.0,  # Reduced from 15s for faster OSINT
        github_token=github_token or scan_config.github_token,
        use_system_dns=scan_config.use_system_dns,
    )

    # Phase 1-2: Infrastructure Discovery (async)
    # Check if discovery should run (PASSIVE/ACTIVE always run, CUSTOM checks module flags)
    should_run_discovery = (
        not scan_config.is_custom_mode() or 
        scan_config.should_run_discovery()
    )
    
    if should_run_discovery:
        assets = await phase_discovery(target, discoverer)
        
        # Filter out-of-scope subdomains based on config blacklist
        if scan_config.scope_blacklist:
            in_scope_subdomains = {
                sub for sub in target.subdomains 
                if scan_config.is_in_scope(sub)
            }
            excluded_count = len(target.subdomains) - len(in_scope_subdomains)
            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} out-of-scope subdomains")
                target.subdomains = in_scope_subdomains
    else:
        logger.info("[Phase 1-2] Infrastructure discovery skipped (disabled in custom mode)")
        # Still need to resolve target domain for other phases
        target.add_ip(target.domain, "0.0.0.0")  # Placeholder

    # Phase 3-4: Technology Fingerprinting (async)
    should_run_fingerprinting = (
        not scan_config.is_custom_mode() or 
        scan_config.should_run_fingerprinting()
    )
    
    if should_run_fingerprinting:
        # Pass discovered hostnames to fingerprinter (only in-scope)
        hostnames_to_scan = [target.domain] + [
            sub for sub in target.subdomains 
            if scan_config.is_in_scope(sub)
        ]
        await phase_fingerprinting(target, fingerprinter, hostnames_to_scan, analyze_content=analyze_content)
    else:
        logger.info("[Phase 3-4] Technology fingerprinting skipped (disabled in custom mode)")

    # Phase 5: OSINT Collection (async)
    should_run_osint = (
        not skip_osint and (
            not scan_config.is_custom_mode() or 
            scan_config.should_run_osint()
        )
    )
    
    if should_run_osint:
        await phase_osint(
            target,
            osint_collector,
            hunter_key=hunter_key or scan_config.hunter_api_key,
            hibp_key=hibp_key or scan_config.hibp_api_key,
            generate_permutations=generate_permutations,
            verify_emails=verify_emails,
        )
    else:
        logger.info("[Phase 5] OSINT collection skipped")

    # Phase 6: Active Reconnaissance
    should_run_active = (
        scan_config.is_active_mode() or 
        (scan_config.is_custom_mode() and scan_config.should_run_active_recon())
    )
    
    if should_run_active:
        logger.info("[Phase 6] Active reconnaissance (zone transfer, dir enum)...")
        active_recon = ActiveRecon(
            config=scan_config,
            timeout=scan_config.http_timeout,
            max_concurrent=50,  # Increased for faster directory enumeration
        )
        active_results = await active_recon.run(target)
        
        # Store directory enumeration results in target
        for host, directories in active_results.discovered_directories.items():
            for dir_info in directories:
                target.add_directory(host, dir_info)
        
        # Store full active recon results
        target.set_active_recon_results(active_results.to_dict())
        
        # Log active recon summary
        total_dirs = sum(len(d) for d in active_results.discovered_directories.values())
        logger.info(f"Active Recon: Zone transfer {'succeeded' if active_results.zone_transfer_success else 'denied'}, {total_dirs} directories found")
    else:
        logger.info("[Phase 6] Active reconnaissance skipped")

    # Phase 7: Port Intelligence (Shodan - passive API lookup)
    should_run_port_intel = (
        scan_config.shodan_api_key and (
            not scan_config.is_custom_mode() or 
            getattr(scan_config, 'module_port_scan', False)
        )
    )
    
    if should_run_port_intel:
        logger.info("[Phase 7] Port intelligence (Shodan API lookup)...")
        port_intel = PortIntel(
            shodan_api_key=scan_config.shodan_api_key,
            rate_limit_delay=1.0,
            timeout=15.0,
        )
        
        # Query all resolved IPs
        all_ips = set()
        for ip_list in target.ips.values():
            all_ips.update(ip_list)
        
        total_ports = 0
        total_services = 0
        
        for ip in all_ips:
            intel = port_intel.query_ip(ip)
            if intel:
                target.add_port_intel(ip, intel.to_dict())
                total_ports += len(intel.ports)
                total_services += len(intel.services)
        
        logger.info(f"Port Intel: {len(all_ips)} IPs queried, {total_ports} ports, {total_services} services found")
    else:
        logger.info("[Phase 7] Port intelligence skipped (no Shodan API key)")

    # Mark scan complete
    target.end_scan()
    logger.info(f"{'=' * 60}")
    logger.info(f"Reconnaissance completed in {target.scan_duration:.2f} seconds")
    logger.info(f"{'=' * 60}")

    # Phase 8: Build Graph (sync - NetworkX operations)
    attack_graph = phase_graph_building(target)

    # Phase 9: Export Results (sync - file I/O)
    phase_export(target, attack_graph, output_dir, generate_report=generate_report)

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

    # Handle interactive mode
    if getattr(args, 'interactive', False):
        scan_config, targets = run_wizard()
        if scan_config is None or not targets:
            logger.info("Interactive wizard cancelled")
            return 0
        
        # Override output directory and log level from wizard config
        if hasattr(scan_config, 'output_dir') and scan_config.output_dir:
            output_path = Path(scan_config.output_dir)
            output_dir = ensure_output_dir(output_path)
            
        if hasattr(scan_config, 'verbose') and scan_config.verbose:
            log_level = logging.DEBUG
            logger = setup_logger(level=log_level, log_file=output_path / "redsurface.log")
        
        logger.info(f"Scan mode: {scan_config.mode.value.upper()}")
        if scan_config.scope_blacklist:
            logger.info(f"Excluded patterns: {', '.join(scan_config.scope_blacklist)}")
    else:
        # Create ScanConfig from arguments
        scan_config = ScanConfig.from_args(args)
        logger.info(f"Scan mode: {scan_config.mode.value.upper()}")
        
        if scan_config.scope_blacklist:
            logger.info(f"Excluded patterns: {', '.join(scan_config.scope_blacklist)}")

        # Initialize target(s) - support for bulk scanning
        targets: List[Target] = []
        
        if args.input_file:
            # Bulk scan mode - load domains from file
            try:
                targets = Target.from_file(args.input_file)
                logger.info(f"Loaded {len(targets)} targets from {args.input_file}")
            except FileNotFoundError as e:
                logger.error(str(e))
                return 1
            except ValueError as e:
                logger.error(str(e))
                return 1
        else:
            # Single target mode
            targets = [Target(domain=args.target)]
            logger.info(f"Target initialized: {targets[0].domain}")

    # Track overall results for bulk scans
    total_success = 0
    total_failed = 0
    all_results = []

    # Run reconnaissance for each target
    for idx, target in enumerate(targets, 1):
        if len(targets) > 1:
            logger.info(f"\n{'='*60}")
            logger.info(f"Processing target {idx}/{len(targets)}: {target.domain}")
            logger.info(f"{'='*60}")

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
                    scan_config=scan_config,
                    generate_report=not args.no_report,
                )
            )
            total_success += 1
            all_results.append({
                "domain": target.domain,
                "status": "success",
                "subdomains": len(target.subdomains),
                "ips": len(target.ips),
                "technologies": sum(len(t) for t in target.technologies.values()),
                "vulnerabilities": sum(len(v) for v in target.vulnerabilities.values()),
                "directories": sum(len(d) for d in target.discovered_directories.values()),
                "ports": sum(len(p.get("ports", [])) for p in target.port_intel.values()),
                "graph_nodes": attack_graph.node_count,
                "graph_edges": attack_graph.edge_count,
                "duration": target.scan_duration,
            })
            
            # Print individual summary
            total_dirs = sum(len(d) for d in target.discovered_directories.values())
            total_ports = sum(len(p.get("ports", [])) for p in target.port_intel.values())
            print("\n" + "=" * 60)
            print("  SCAN SUMMARY")
            print("=" * 60)
            print(f"  Target:          {target.domain}")
            print(f"  Mode:            {scan_config.mode.value.upper()}")
            print(f"  Subdomains:      {len(target.subdomains)}")
            print(f"  IPs Resolved:    {len(target.ips)}")
            print(f"  Technologies:    {sum(len(t) for t in target.technologies.values())}")
            print(f"  Vulnerabilities: {sum(len(v) for v in target.vulnerabilities.values())}")
            print(f"  Directories:     {total_dirs}")
            print(f"  Open Ports:      {total_ports}")
            print(f"  Emails Found:    {len(target.emails)}")
            print(f"  People Found:    {len(target.people)}")
            print(f"  Graph Nodes:     {attack_graph.node_count}")
            print(f"  Graph Edges:     {attack_graph.edge_count}")
            print(f"  Scan Duration:   {target.scan_duration:.2f}s")
            print("=" * 60)
            print(f"  Output:          {output_dir}")
            print("=" * 60 + "\n")

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            return 130
        except Exception as e:
            logger.exception(f"Error scanning {target.domain}: {e}")
            total_failed += 1
            all_results.append({
                "domain": target.domain,
                "status": "failed",
                "error": str(e),
            })
            continue

    # Print bulk scan summary if multiple targets
    if len(targets) > 1:
        print("\n" + "=" * 60)
        print("  BULK SCAN SUMMARY")
        print("=" * 60)
        print(f"  Total Targets:   {len(targets)}")
        print(f"  Successful:      {total_success}")
        print(f"  Failed:          {total_failed}")
        print("=" * 60)
        
        # Save bulk results summary
        bulk_summary_path = output_dir / "bulk_scan_summary.json"
        with open(bulk_summary_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, default=str)
        logger.info(f"Bulk scan summary saved to: {bulk_summary_path}")

    logger.info("RedSurface completed successfully ✓")
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
