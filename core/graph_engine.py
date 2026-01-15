"""
Attack Surface Graph Engine for RedSurface.
Builds and visualizes the attack surface intelligence graph using NetworkX and PyVis.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import networkx as nx
from pyvis.network import Network

from utils.logger import get_logger


# Node type color scheme
NODE_COLORS: Dict[str, str] = {
    "Domain": "#6366f1",        # Indigo - Root domain
    "Subdomain": "#8b5cf6",     # Purple - Subdomains
    "IP": "#22c55e",            # Green - Regular IP
    "IP_Cloud": "#f97316",      # Orange - Cloud-hosted IP
    "CloudService": "#fb923c",  # Light Orange - Cloud provider
    "Technology": "#3b82f6",    # Blue - Technologies
    "Vulnerability": "#ef4444", # Red - Vulnerabilities
    "Email": "#ffd700",         # Gold - Email addresses
    "Person": "#ffc0cb",        # Pink - People
}

# Node type shapes
NODE_SHAPES: Dict[str, str] = {
    "Domain": "diamond",
    "Subdomain": "dot",
    "IP": "dot",
    "IP_Cloud": "dot",
    "CloudService": "box",
    "Technology": "box",
    "Vulnerability": "triangle",
    "Email": "box",
    "Person": "ellipse",
}

# Node type sizes
NODE_SIZES: Dict[str, int] = {
    "Domain": 40,
    "Subdomain": 25,
    "IP": 20,
    "IP_Cloud": 20,
    "CloudService": 25,
    "Technology": 22,
    "Vulnerability": 28,
    "Email": 22,
    "Person": 25,
}

# Edge colors by type
EDGE_COLORS: Dict[str, str] = {
    "HAS_SUBDOMAIN": "#a78bfa",  # Light purple
    "RESOLVES_TO": "#4ade80",    # Light green
    "HOSTED_ON": "#fdba74",      # Light orange
    "RUNS": "#60a5fa",           # Light blue
    "EXPOSES": "#60a5fa",        # Light blue
    "AFFECTED_BY": "#f87171",    # Light red
    "USES": "#ffb6c1",           # Light pink - Person uses Email
    "BELONGS_TO": "#ffe066",     # Light gold - Email belongs to Domain
}


class AttackSurfaceGraph:
    """
    Builds and manages the Attack Surface Intelligence Graph.
    
    Provides methods to add assets, technologies, and vulnerabilities,
    then export to interactive HTML visualization.
    """

    def __init__(self, title: str = "Attack Surface Graph") -> None:
        """
        Initialize the attack surface graph.

        Args:
            title: Title for the graph visualization
        """
        self.graph: nx.DiGraph = nx.DiGraph()
        self.title = title
        self.logger = get_logger()
        self._added_nodes: Set[str] = set()
        self._added_edges: Set[tuple] = set()

    def _add_node(
        self,
        node_id: str,
        node_type: str,
        label: Optional[str] = None,
        is_cloud: bool = False,
        **attrs: Any,
    ) -> None:
        """
        Add a node to the graph with proper styling.

        Args:
            node_id: Unique identifier for the node
            node_type: Type of node (Domain, Subdomain, IP, etc.)
            label: Display label (defaults to node_id)
            is_cloud: Whether this is a cloud-hosted resource
            **attrs: Additional node attributes
        """
        if node_id in self._added_nodes:
            return

        # Determine color based on cloud status
        if node_type == "IP" and is_cloud:
            color = NODE_COLORS["IP_Cloud"]
            actual_type = "IP_Cloud"
        else:
            color = NODE_COLORS.get(node_type, "#94a3b8")
            actual_type = node_type

        self.graph.add_node(
            node_id,
            label=label or node_id,
            node_type=node_type,
            color=color,
            shape=NODE_SHAPES.get(actual_type, "dot"),
            size=NODE_SIZES.get(actual_type, 20),
            is_cloud=is_cloud,
            **attrs,
        )
        self._added_nodes.add(node_id)

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        **attrs: Any,
    ) -> None:
        """
        Add an edge to the graph with proper styling.

        Args:
            source: Source node ID
            target: Target node ID
            edge_type: Type of relationship
            **attrs: Additional edge attributes
        """
        edge_key = (source, target, edge_type)
        if edge_key in self._added_edges:
            return

        self.graph.add_edge(
            source,
            target,
            edge_type=edge_type,
            title=edge_type,
            label=edge_type,
            color=EDGE_COLORS.get(edge_type, "#94a3b8"),
            arrows="to",
            **attrs,
        )
        self._added_edges.add(edge_key)

    def add_domain(self, domain: str) -> None:
        """
        Add the root domain node.

        Args:
            domain: Root domain name
        """
        self._add_node(
            node_id=domain,
            node_type="Domain",
            label=f"🌐 {domain}",
            title=f"Root Domain: {domain}",
        )

    def add_subdomain(self, subdomain: str, parent_domain: str) -> None:
        """
        Add a subdomain node and link to parent domain.

        Args:
            subdomain: Subdomain hostname
            parent_domain: Parent domain name
        """
        self._add_node(
            node_id=subdomain,
            node_type="Subdomain",
            label=subdomain,
            title=f"Subdomain: {subdomain}",
        )
        self._add_edge(parent_domain, subdomain, "HAS_SUBDOMAIN")

    def add_ip(
        self,
        ip: str,
        hostname: str,
        is_cloud: bool = False,
        cloud_provider: Optional[str] = None,
    ) -> None:
        """
        Add an IP node and RESOLVES_TO edge.

        Args:
            ip: IP address
            hostname: Hostname that resolves to this IP
            is_cloud: Whether IP is cloud-hosted
            cloud_provider: Name of cloud provider if applicable
        """
        label = f"☁️ {ip}" if is_cloud else f"🖥️ {ip}"
        title = f"IP: {ip}"
        if cloud_provider:
            title += f"\nCloud: {cloud_provider}"

        self._add_node(
            node_id=ip,
            node_type="IP",
            label=label,
            title=title,
            is_cloud=is_cloud,
            cloud_provider=cloud_provider,
        )
        self._add_edge(hostname, ip, "RESOLVES_TO")

        # Add cloud service node if applicable
        if cloud_provider:
            self.add_cloud_service(ip, cloud_provider)

    def add_cloud_service(self, ip: str, provider: str) -> None:
        """
        Add a cloud service node and HOSTED_ON edge.

        Args:
            ip: IP address hosted on the cloud
            provider: Cloud provider name
        """
        cloud_node_id = f"cloud:{provider}"
        self._add_node(
            node_id=cloud_node_id,
            node_type="CloudService",
            label=f"☁️ {provider}",
            title=f"Cloud Provider: {provider}",
        )
        self._add_edge(ip, cloud_node_id, "HOSTED_ON")

    def add_technology(
        self,
        tech_name: str,
        host: str,
        version: Optional[str] = None,
    ) -> None:
        """
        Add a technology node and RUNS edge from host.

        Args:
            tech_name: Technology name
            host: Hostname or IP running this technology
            version: Optional version string
        """
        full_name = f"{tech_name} {version}" if version else tech_name
        tech_node_id = f"tech:{full_name}"

        self._add_node(
            node_id=tech_node_id,
            node_type="Technology",
            label=f"⚙️ {full_name}",
            title=f"Technology: {full_name}",
            tech_name=tech_name,
            version=version,
        )
        self._add_edge(host, tech_node_id, "RUNS")

    def add_vulnerability(
        self,
        cve_id: str,
        tech_node_id: str,
        severity: str = "Unknown",
        cvss_score: Optional[float] = None,
        description: Optional[str] = None,
    ) -> None:
        """
        Add a vulnerability node and AFFECTED_BY edge.

        Args:
            cve_id: CVE identifier
            tech_node_id: Technology node that is affected
            severity: Severity level (Critical, High, Medium, Low)
            cvss_score: CVSS score if available
            description: CVE description
        """
        vuln_node_id = f"vuln:{cve_id}"
        
        # Build tooltip
        title_parts = [f"CVE: {cve_id}", f"Severity: {severity}"]
        if cvss_score:
            title_parts.append(f"CVSS: {cvss_score}")
        if description:
            title_parts.append(f"Description: {description[:100]}...")
        
        self._add_node(
            node_id=vuln_node_id,
            node_type="Vulnerability",
            label=f"⚠️ {cve_id}",
            title="\n".join(title_parts),
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
        )
        self._add_edge(tech_node_id, vuln_node_id, "AFFECTED_BY")

    def add_email(self, email: str, domain: str) -> None:
        """
        Add an email node and BELONGS_TO edge to domain.

        Args:
            email: Email address
            domain: Domain the email belongs to
        """
        email_node_id = f"email:{email}"
        self._add_node(
            node_id=email_node_id,
            node_type="Email",
            label=f"📧 {email}",
            title=f"Email: {email}",
        )
        self._add_edge(email_node_id, domain, "BELONGS_TO")

    def add_person(self, name: str, email: Optional[str] = None) -> None:
        """
        Add a person node and USES edge to their email if available.

        Args:
            name: Person's name
            email: Optional email address used by this person
        """
        person_node_id = f"person:{name}"
        self._add_node(
            node_id=person_node_id,
            node_type="Person",
            label=f"👤 {name}",
            title=f"Person: {name}",
        )
        
        # Connect person to their email if available
        if email:
            email_node_id = f"email:{email}"
            # Ensure email node exists
            if email_node_id not in self._added_nodes:
                # Add email without domain connection (domain unknown from person context)
                self._add_node(
                    node_id=email_node_id,
                    node_type="Email",
                    label=f"📧 {email}",
                    title=f"Email: {email}",
                )
            self._add_edge(person_node_id, email_node_id, "USES")

    def add_asset(self, asset_data: Dict[str, Any]) -> None:
        """
        Add a complete asset with all related nodes and edges.

        Expected asset_data structure:
        {
            "hostname": str,
            "ips": List[str],
            "cloud_providers": List[str],
            "technologies": List[{
                "name": str,
                "version": str,
                "cves": List[{"cve_id": str, "severity": str, "cvss_score": float}]
            }]
        }

        Args:
            asset_data: Dictionary containing asset information
        """
        hostname = asset_data.get("hostname", "")
        if not hostname:
            return

        is_cloud = bool(asset_data.get("cloud_providers"))
        cloud_provider = asset_data["cloud_providers"][0] if is_cloud else None

        # Add IPs
        for ip in asset_data.get("ips", []):
            self.add_ip(
                ip=ip,
                hostname=hostname,
                is_cloud=is_cloud,
                cloud_provider=cloud_provider,
            )

        # Add technologies
        for tech in asset_data.get("technologies", []):
            tech_name = tech.get("name", "Unknown")
            version = tech.get("version")
            full_name = f"{tech_name} {version}" if version else tech_name

            # Connect tech to hostname (or first IP if available)
            connect_to = hostname
            self.add_technology(tech_name, connect_to, version)

            # Add vulnerabilities
            tech_node_id = f"tech:{full_name}"
            for cve in tech.get("cves", []):
                self.add_vulnerability(
                    cve_id=cve.get("cve_id", "Unknown"),
                    tech_node_id=tech_node_id,
                    severity=cve.get("severity", "Unknown"),
                    cvss_score=cve.get("cvss_score"),
                    description=cve.get("description"),
                )

    def build_from_target(self, target: "Target") -> None:
        """
        Build the complete graph from a Target object.

        Args:
            target: Target instance with reconnaissance data
        """
        # Add root domain
        self.add_domain(target.domain)

        # Add subdomains
        for subdomain in target.subdomains:
            self.add_subdomain(subdomain, target.domain)

        # Add IPs with cloud detection
        for hostname, ips in target.ips.items():
            for ip in ips:
                cloud_provider = target.cloud_services.get(ip)
                self.add_ip(
                    ip=ip,
                    hostname=hostname,
                    is_cloud=bool(cloud_provider),
                    cloud_provider=cloud_provider,
                )

        # Add technologies
        for hostname, techs in target.technologies.items():
            for tech in techs:
                # Parse tech name and version if combined
                if " " in tech and any(c.isdigit() for c in tech):
                    parts = tech.rsplit(" ", 1)
                    tech_name = parts[0]
                    version = parts[1] if len(parts) > 1 else None
                else:
                    tech_name = tech
                    version = None

                self.add_technology(tech_name, hostname, version)

                # Add vulnerabilities for this tech
                tech_node_id = f"tech:{tech}"
                for cve_id in target.vulnerabilities.get(tech, []):
                    self.add_vulnerability(
                        cve_id=cve_id,
                        tech_node_id=tech_node_id,
                        severity="High",  # Default severity
                    )

        # Add emails and connect to domain
        for email in target.emails:
            self.add_email(email, target.domain)

        # Add people and connect to their emails
        for person in target.people:
            name = person.get("name", "Unknown")
            email = person.get("email")
            self.add_person(name, email)

        self.logger.info(
            f"Graph built: {self.node_count} nodes, {self.edge_count} edges"
        )

    @property
    def node_count(self) -> int:
        """Return the number of nodes in the graph."""
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Return the number of edges in the graph."""
        return self.graph.number_of_edges()

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the graph."""
        stats: Dict[str, int] = {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
        }

        # Count by node type
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "Unknown")
            key = f"nodes_{node_type.lower()}"
            stats[key] = stats.get(key, 0) + 1

        return stats

    def export_html(
        self,
        filename: str,
        height: str = "800px",
        width: str = "100%",
        physics: bool = True,
        notebook: bool = False,
    ) -> Path:
        """
        Export the graph to an interactive HTML file using PyVis.

        Args:
            filename: Output filename (will add .html if not present)
            height: Height of the visualization
            width: Width of the visualization
            physics: Enable physics simulation
            notebook: Whether running in a notebook environment

        Returns:
            Path to the generated HTML file
        """
        if not filename.endswith(".html"):
            filename += ".html"

        filepath = Path(filename)

        # Create PyVis network
        net = Network(
            height=height,
            width=width,
            directed=True,
            notebook=notebook,
            bgcolor="#1e1e2e",  # Dark background
            font_color="#cdd6f4",  # Light text
        )

        # Configure physics
        if physics:
            net.set_options("""
            {
                "physics": {
                    "enabled": true,
                    "forceAtlas2Based": {
                        "gravitationalConstant": -50,
                        "centralGravity": 0.01,
                        "springLength": 150,
                        "springConstant": 0.08,
                        "damping": 0.4
                    },
                    "solver": "forceAtlas2Based",
                    "stabilization": {
                        "enabled": true,
                        "iterations": 200,
                        "updateInterval": 25
                    }
                },
                "nodes": {
                    "font": {
                        "size": 14,
                        "color": "#cdd6f4"
                    },
                    "borderWidth": 2,
                    "borderWidthSelected": 4
                },
                "edges": {
                    "font": {
                        "size": 10,
                        "color": "#6c7086",
                        "align": "middle"
                    },
                    "smooth": {
                        "type": "curvedCW",
                        "roundness": 0.2
                    },
                    "arrows": {
                        "to": {
                            "enabled": true,
                            "scaleFactor": 0.5
                        }
                    }
                },
                "interaction": {
                    "hover": true,
                    "tooltipDelay": 200,
                    "hideEdgesOnDrag": true,
                    "navigationButtons": true,
                    "keyboard": {
                        "enabled": true
                    }
                }
            }
            """)

        # Add nodes from NetworkX graph
        for node, data in self.graph.nodes(data=True):
            net.add_node(
                node,
                label=data.get("label", node),
                title=data.get("title", node),
                color=data.get("color", "#94a3b8"),
                shape=data.get("shape", "dot"),
                size=data.get("size", 20),
            )

        # Add edges from NetworkX graph
        for source, target, data in self.graph.edges(data=True):
            net.add_edge(
                source,
                target,
                title=data.get("edge_type", ""),
                color=data.get("color", "#94a3b8"),
            )

        # Add legend HTML
        legend_html = self._generate_legend_html()

        # Generate HTML
        net.save_graph(str(filepath))

        # Inject custom legend into the HTML
        self._inject_legend(filepath, legend_html)

        self.logger.info(f"Graph exported to: {filepath}")
        return filepath

    def _generate_legend_html(self) -> str:
        """Generate HTML legend for node types."""
        legend_items = [
            ("Domain", NODE_COLORS["Domain"], "◆"),
            ("Subdomain", NODE_COLORS["Subdomain"], "●"),
            ("IP", NODE_COLORS["IP"], "●"),
            ("Cloud IP", NODE_COLORS["IP_Cloud"], "●"),
            ("Technology", NODE_COLORS["Technology"], "■"),
            ("Vulnerability", NODE_COLORS["Vulnerability"], "▲"),
        ]

        items_html = ""
        for name, color, symbol in legend_items:
            items_html += f'''
            <div style="display: flex; align-items: center; margin: 5px 0;">
                <span style="color: {color}; font-size: 16px; margin-right: 8px;">{symbol}</span>
                <span>{name}</span>
            </div>
            '''

        return f'''
        <div id="legend" style="
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(30, 30, 46, 0.9);
            border: 1px solid #45475a;
            border-radius: 8px;
            padding: 15px;
            color: #cdd6f4;
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
            z-index: 1000;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        ">
            <div style="font-weight: bold; margin-bottom: 10px; border-bottom: 1px solid #45475a; padding-bottom: 8px;">
                🎯 Attack Surface Graph
            </div>
            {items_html}
            <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #45475a; font-size: 11px; color: #6c7086;">
                Nodes: {self.node_count} | Edges: {self.edge_count}
            </div>
        </div>
        '''

    def _inject_legend(self, filepath: Path, legend_html: str) -> None:
        """Inject legend HTML into the generated graph file."""
        try:
            content = filepath.read_text(encoding="utf-8")
            # Insert legend before closing body tag
            content = content.replace("</body>", f"{legend_html}</body>")
            filepath.write_text(content, encoding="utf-8")
        except Exception as e:
            self.logger.warning(f"Could not inject legend: {e}")

    def export_json(self, filename: str) -> Path:
        """
        Export the graph data to JSON format.

        Args:
            filename: Output filename

        Returns:
            Path to the generated JSON file
        """
        if not filename.endswith(".json"):
            filename += ".json"

        filepath = Path(filename)

        # Build JSON structure
        data = {
            "title": self.title,
            "stats": self.get_stats(),
            "nodes": [],
            "edges": [],
        }

        for node, attrs in self.graph.nodes(data=True):
            data["nodes"].append({
                "id": node,
                **{k: v for k, v in attrs.items() if k != "title"},
            })

        for source, target, attrs in self.graph.edges(data=True):
            data["edges"].append({
                "source": source,
                "target": target,
                "type": attrs.get("edge_type", "UNKNOWN"),
            })

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Graph data exported to: {filepath}")
        return filepath
