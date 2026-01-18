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


# Node type color scheme (must match group colors in export_html options)
NODE_COLORS: Dict[str, str] = {
    "Domain": "#6366f1",        # Indigo - Root domain
    "Subdomain": "#8b5cf6",     # Purple - Subdomains
    "IP": "#22c55e",            # Green - Regular IP
    "IP_Cloud": "#f97316",      # Orange - Cloud-hosted IP
    "CloudService": "#fb923c",  # Light Orange - Cloud provider
    "Technology": "#3b82f6",    # Blue - Technologies
    "Vulnerability": "#ef4444", # Red - Vulnerabilities
    "Email": "#eab308",         # Yellow - Email addresses
    "Person": "#ec4899",        # Pink - People
    "Directory": "#f59e0b",     # Amber/Gold - Discovered directories (folder-like)
    "Port": "#06b6d4",          # Cyan - Open ports
    "Service": "#0ea5e9",       # Sky blue - Services running on ports
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
    "Directory": "star",  # Star shape for directories - distinct and visible
    "Port": "hexagon",          # Hexagon for ports
    "Service": "box",           # Box for services
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
    "Directory": 18,  # Slightly smaller to reduce crowding
    "Port": 18,
    "Service": 20,
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
    "HAS_PATH": "#fbbf24",       # Amber - Host has discovered path (matches Directory)
    "HAS_PORT": "#22d3ee",       # Light cyan - IP has open port
    "RUNS_SERVICE": "#38bdf8",   # Light sky - Port runs service
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

    def add_directory(
        self,
        path: str,
        host: str,
        status_code: int = 200,
        content_length: Optional[int] = None,
    ) -> None:
        """
        Add a discovered directory/file node and HAS_PATH edge to host.

        Args:
            path: The discovered path (e.g., /admin, /.git)
            host: Hostname where the path was discovered
            status_code: HTTP status code returned
            content_length: Response content length if available
        """
        # Create unique node ID
        dir_node_id = f"dir:{host}/{path.lstrip('/')}"
        
        # Color based on status code
        if status_code == 200:
            emoji = "📂"
            status_text = "OK"
        elif status_code == 403:
            emoji = "🔒"
            status_text = "Forbidden"
        elif status_code == 401:
            emoji = "🔐"
            status_text = "Auth Required"
        elif status_code in [301, 302, 307, 308]:
            emoji = "↪️"
            status_text = "Redirect"
        else:
            emoji = "📄"
            status_text = str(status_code)
        
        # Build tooltip
        title_parts = [f"Path: /{path.lstrip('/')}", f"Status: {status_code} ({status_text})"]
        if content_length:
            title_parts.append(f"Size: {content_length} bytes")
        
        self._add_node(
            node_id=dir_node_id,
            node_type="Directory",
            label=f"{emoji} /{path.lstrip('/')}",
            title="\n".join(title_parts),
            path=path,
            status_code=status_code,
            content_length=content_length,
        )
        self._add_edge(host, dir_node_id, "HAS_PATH")

    def add_port(
        self,
        ip: str,
        port: int,
        protocol: str = "tcp",
        service: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> None:
        """
        Add an open port node and HAS_PORT edge to IP.

        Args:
            ip: IP address where the port is open
            port: Port number
            protocol: Protocol (tcp/udp)
            service: Service name detected on the port
            version: Service version if detected
            banner: Banner/response data
        """
        port_node_id = f"port:{ip}:{port}/{protocol}"
        
        # Build label and tooltip
        label = f"🔌 {port}/{protocol}"
        title_parts = [f"Port: {port}/{protocol}", f"IP: {ip}"]
        
        if service:
            title_parts.append(f"Service: {service}")
            if version:
                title_parts.append(f"Version: {version}")
        
        if banner:
            # Truncate banner for tooltip
            banner_preview = banner[:100] + "..." if len(banner) > 100 else banner
            title_parts.append(f"Banner: {banner_preview}")
        
        self._add_node(
            node_id=port_node_id,
            node_type="Port",
            label=label,
            title="\n".join(title_parts),
            port=port,
            protocol=protocol,
            service=service,
            version=version,
        )
        self._add_edge(ip, port_node_id, "HAS_PORT")
        
        # If service detected, add service node
        if service:
            self.add_service(port_node_id, service, version)

    def add_service(
        self,
        port_node_id: str,
        service: str,
        version: Optional[str] = None,
    ) -> None:
        """
        Add a service node connected to a port.

        Args:
            port_node_id: The port node ID to connect to
            service: Service name
            version: Service version
        """
        service_label = service
        if version:
            service_label = f"{service} {version}"
        
        service_node_id = f"svc:{service_label}".replace(" ", "_")
        
        title = f"Service: {service}"
        if version:
            title += f"\nVersion: {version}"
        
        self._add_node(
            node_id=service_node_id,
            node_type="Service",
            label=f"⚙️ {service_label}",
            title=title,
            service=service,
            version=version,
        )
        self._add_edge(port_node_id, service_node_id, "RUNS_SERVICE")

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

        # Add discovered directories (Active Recon results)
        if hasattr(target, 'discovered_directories') and target.discovered_directories:
            for host, directories in target.discovered_directories.items():
                for dir_info in directories:
                    self.add_directory(
                        path=dir_info.get("path", ""),
                        host=host,
                        status_code=dir_info.get("status_code", 200),
                        content_length=dir_info.get("content_length"),
                    )

        # Add port intelligence data (Shodan results)
        if hasattr(target, 'port_intel') and target.port_intel:
            for ip, intel in target.port_intel.items():
                # Add ports
                for port in intel.get("ports", []):
                    self.add_port(
                        ip=ip,
                        port=port,
                        protocol="tcp",  # Default to TCP
                    )
                
                # Add detailed service info if available
                for service_info in intel.get("services", []):
                    port_num = service_info.get("port")
                    if port_num:
                        port_node_id = f"port:{ip}:{port_num}/tcp"
                        # Update port node with service info
                        if port_node_id in self.graph.nodes:
                            self.graph.nodes[port_node_id]["service"] = service_info.get("service")
                            self.graph.nodes[port_node_id]["version"] = service_info.get("version")
                            self.graph.nodes[port_node_id]["banner"] = service_info.get("banner")

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
        Uses BloodHound-style forceAtlas2Based layout for clean visualization.

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

        # Configure BloodHound-style physics layout
        if physics:
            options = """
            var options = {
              "groups": {
                "Domain": {
                  "color": { "background": "#6366f1", "border": "#4f46e5", "highlight": { "background": "#818cf8", "border": "#4f46e5" } },
                  "shape": "diamond",
                  "font": { "color": "#cdd6f4" }
                },
                "Subdomain": {
                  "color": { "background": "#8b5cf6", "border": "#7c3aed", "highlight": { "background": "#a78bfa", "border": "#7c3aed" } },
                  "shape": "dot",
                  "font": { "color": "#cdd6f4" }
                },
                "IP": {
                  "color": { "background": "#22c55e", "border": "#16a34a", "highlight": { "background": "#4ade80", "border": "#16a34a" } },
                  "shape": "dot",
                  "font": { "color": "#cdd6f4" }
                },
                "IP_Cloud": {
                  "color": { "background": "#f97316", "border": "#ea580c", "highlight": { "background": "#fb923c", "border": "#ea580c" } },
                  "shape": "dot",
                  "font": { "color": "#cdd6f4" }
                },
                "CloudService": {
                  "color": { "background": "#fb923c", "border": "#f97316", "highlight": { "background": "#fdba74", "border": "#f97316" } },
                  "shape": "box",
                  "font": { "color": "#1e1e2e" }
                },
                "Technology": {
                  "color": { "background": "#3b82f6", "border": "#2563eb", "highlight": { "background": "#60a5fa", "border": "#2563eb" } },
                  "shape": "box",
                  "font": { "color": "#ffffff" }
                },
                "Vulnerability": {
                  "color": { "background": "#ef4444", "border": "#dc2626", "highlight": { "background": "#f87171", "border": "#dc2626" } },
                  "shape": "triangle",
                  "font": { "color": "#cdd6f4" }
                },
                "Email": {
                  "color": { "background": "#eab308", "border": "#ca8a04", "highlight": { "background": "#facc15", "border": "#ca8a04" } },
                  "shape": "box",
                  "font": { "color": "#1e1e2e" }
                },
                "Person": {
                  "color": { "background": "#ec4899", "border": "#db2777", "highlight": { "background": "#f472b6", "border": "#db2777" } },
                  "shape": "ellipse",
                  "font": { "color": "#cdd6f4" }
                },
                "Directory": {
                  "color": { "background": "#f59e0b", "border": "#d97706", "highlight": { "background": "#fbbf24", "border": "#d97706" } },
                  "shape": "star",
                  "font": { "color": "#1e1e2e" }
                },
                "Port": {
                  "color": { "background": "#06b6d4", "border": "#0891b2", "highlight": { "background": "#22d3ee", "border": "#0891b2" } },
                  "shape": "hexagon",
                  "font": { "color": "#1e1e2e" }
                },
                "Service": {
                  "color": { "background": "#0ea5e9", "border": "#0284c7", "highlight": { "background": "#38bdf8", "border": "#0284c7" } },
                  "shape": "box",
                  "font": { "color": "#ffffff" }
                }
              },
              "nodes": {
                "font": { "size": 16, "strokeWidth": 2, "color": "#cdd6f4" },
                "scaling": { "min": 10, "max": 30 },
                "borderWidth": 2,
                "borderWidthSelected": 4
              },
              "edges": {
                "color": { "inherit": false },
                "smooth": { "type": "continuous", "forceDirection": "none" },
                "font": {
                  "size": 10,
                  "color": "#6c7086",
                  "align": "middle"
                },
                "arrows": {
                  "to": {
                    "enabled": true,
                    "scaleFactor": 0.5
                  }
                }
              },
              "physics": {
                "hierarchicalRepulsion": {
                  "centralGravity": 0.0,
                  "springLength": 180,
                  "springConstant": 0.008,
                  "nodeDistance": 220,
                  "damping": 0.12,
                  "avoidOverlap": 1
                },
                "maxVelocity": 40,
                "solver": "hierarchicalRepulsion",
                "timestep": 0.4,
                "stabilization": { 
                  "enabled": true,
                  "iterations": 250,
                  "updateInterval": 25
                }
              },
              "layout": {
                "hierarchical": {
                  "enabled": true,
                  "levelSeparation": 250,
                  "nodeSpacing": 200,
                  "treeSpacing": 300,
                  "blockShifting": true,
                  "edgeMinimization": true,
                  "parentCentralization": true,
                  "direction": "UD",
                  "sortMethod": "directed"
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
            """
            net.set_options(options)

        # Add nodes from NetworkX graph with group attribute for filtering
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "Unknown")
            net.add_node(
                node,
                label=data.get("label", node),
                title=data.get("title", node),
                color=data.get("color", "#94a3b8"),
                shape=data.get("shape", "dot"),
                size=data.get("size", 20),
                group=node_type,  # Add group for filtering
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
        
        # Inject custom filter sidebar JavaScript
        self._inject_custom_javascript(filepath)

        self.logger.info(f"Graph exported to: {filepath}")
        return filepath

    def _generate_legend_html(self) -> str:
        """Generate HTML legend for node types."""
        legend_items = [
            ("Domain", NODE_COLORS["Domain"], "◆"),
            ("Subdomain", NODE_COLORS["Subdomain"], "●"),
            ("IP", NODE_COLORS["IP"], "●"),
            ("Cloud", NODE_COLORS["CloudService"], "■"),
            ("Technology", NODE_COLORS["Technology"], "■"),
            ("Vulnerability", NODE_COLORS["Vulnerability"], "▲"),
            ("Directory", NODE_COLORS["Directory"], "★"),
            ("Port", NODE_COLORS["Port"], "⬡"),
            ("Service", NODE_COLORS["Service"], "■"),
            ("Email", NODE_COLORS["Email"], "■"),
            ("Person", NODE_COLORS["Person"], "●"),
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

    def _inject_custom_javascript(self, filepath: Path) -> None:
        """
        Inject custom filter sidebar JavaScript into the generated HTML.
        Provides BloodHound-style node type filtering.
        
        Args:
            filepath: Path to the HTML file to modify
        """
        # Filter sidebar HTML/CSS
        filter_sidebar_html = '''
        <!-- Filter Sidebar -->
        <div id="filterSidebar" style="
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(30, 30, 46, 0.95);
            border: 1px solid #45475a;
            border-radius: 8px;
            padding: 15px;
            color: #cdd6f4;
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
            z-index: 1000;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            min-width: 200px;
            max-height: 90vh;
            overflow-y: auto;
        ">
            <div style="font-weight: bold; margin-bottom: 12px; border-bottom: 1px solid #45475a; padding-bottom: 8px; display: flex; align-items: center;">
                <span style="margin-right: 8px;">🔍</span> Filter Nodes
            </div>
            
            <!-- Search Input -->
            <div style="margin-bottom: 12px;">
                <input type="text" id="nodeSearch" placeholder="Search nodes..." oninput="searchNodes(this.value)" style="
                    width: 100%;
                    padding: 8px 10px;
                    background: #313244;
                    border: 1px solid #45475a;
                    border-radius: 4px;
                    color: #cdd6f4;
                    font-size: 12px;
                    outline: none;
                    box-sizing: border-box;
                " onfocus="this.style.borderColor='#3b82f6'" onblur="this.style.borderColor='#45475a'">
                <div id="searchResults" style="font-size: 11px; color: #6c7086; margin-top: 4px;"></div>
            </div>
            
            <div class="filter-group" style="display: flex; flex-direction: column; gap: 6px;">
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Domain" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #6366f1; margin-right: 6px;">◆</span> Domain
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Subdomain" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #8b5cf6; margin-right: 6px;">●</span> Subdomain
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-IP" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #22c55e; margin-right: 6px;">●</span> IP
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-CloudService" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #fb923c; margin-right: 6px;">■</span> Cloud
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Technology" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #3b82f6; margin-right: 6px;">■</span> Technology
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Vulnerability" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #ef4444; margin-right: 6px;">▲</span> Vulnerability
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Directory" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #f59e0b; margin-right: 6px;">★</span> Directory
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Port" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #06b6d4; margin-right: 6px;">⬡</span> Port
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Service" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #0ea5e9; margin-right: 6px;">■</span> Service
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Email" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #eab308; margin-right: 6px;">■</span> Email
                </label>
                
                <label class="filter-item" style="display: flex; align-items: center; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: background 0.2s;">
                    <input type="checkbox" id="filter-Person" checked onchange="filterNodes()" style="margin-right: 10px; cursor: pointer;">
                    <span style="color: #ec4899; margin-right: 6px;">●</span> Person
                </label>
            </div>
            
            <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid #45475a;">
                <button onclick="showAllNodes()" style="
                    width: 100%;
                    padding: 8px 12px;
                    background: #3b82f6;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 12px;
                    transition: background 0.2s;
                " onmouseover="this.style.background='#2563eb'" onmouseout="this.style.background='#3b82f6'">
                    Show All
                </button>
                <button onclick="hideAllNodes()" style="
                    width: 100%;
                    padding: 8px 12px;
                    margin-top: 6px;
                    background: #45475a;
                    color: #cdd6f4;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 12px;
                    transition: background 0.2s;
                " onmouseover="this.style.background='#585b70'" onmouseout="this.style.background='#45475a'">
                    Hide All
                </button>
            </div>
            
            <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #45475a; font-size: 11px; color: #6c7086;">
                <span id="visibleCount">All nodes visible</span>
            </div>
            
            <!-- Layout Toggle Section -->
            <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid #45475a;">
                <div style="font-weight: bold; margin-bottom: 8px; font-size: 12px;">📐 Layout Mode</div>
                <div style="display: flex; gap: 6px;">
                    <button id="btn-hierarchical" onclick="setLayout('hierarchical')" style="
                        flex: 1;
                        padding: 6px 8px;
                        background: #3b82f6;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 11px;
                        transition: all 0.2s;
                    ">
                        🌳 Tree
                    </button>
                    <button id="btn-force" onclick="setLayout('force')" style="
                        flex: 1;
                        padding: 6px 8px;
                        background: #45475a;
                        color: #cdd6f4;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 11px;
                        transition: all 0.2s;
                    ">
                        🕸️ Force
                    </button>
                </div>
            </div>
        </div>
        
        <style>
            .filter-item:hover {
                background: rgba(69, 71, 90, 0.5);
            }
            #filterSidebar::-webkit-scrollbar {
                width: 6px;
            }
            #filterSidebar::-webkit-scrollbar-track {
                background: #1e1e2e;
            }
            #filterSidebar::-webkit-scrollbar-thumb {
                background: #45475a;
                border-radius: 3px;
            }
            #filterSidebar::-webkit-scrollbar-thumb:hover {
                background: #585b70;
            }
            #nodeSearch::placeholder {
                color: #6c7086;
            }
        </style>
        '''

        # Filter JavaScript function
        filter_script = '''
        <script type="text/javascript">
            // Store original node data for restoration
            var originalNodes = null;
            var originalEdges = null;
            var searchQuery = '';
            
            // Initialize on page load
            document.addEventListener('DOMContentLoaded', function() {
                // Wait for network to be ready
                setTimeout(function() {
                    if (typeof nodes !== 'undefined' && typeof edges !== 'undefined') {
                        originalNodes = nodes.get();
                        originalEdges = edges.get();
                        updateVisibleCount();
                    }
                }, 500);
            });
            
            // Search nodes by label
            function searchNodes(query) {
                searchQuery = query.toLowerCase().trim();
                
                if (!originalNodes) {
                    originalNodes = nodes.get();
                    originalEdges = edges.get();
                }
                
                applyFilters();
                
                // Update search results indicator
                var resultsDiv = document.getElementById('searchResults');
                if (searchQuery) {
                    var matchCount = originalNodes.filter(function(node) {
                        return (node.label || '').toLowerCase().includes(searchQuery) || 
                               (node.id || '').toLowerCase().includes(searchQuery);
                    }).length;
                    resultsDiv.textContent = matchCount + ' matches found';
                } else {
                    resultsDiv.textContent = '';
                }
            }
            
            // Filter nodes based on checkbox states and search query
            function filterNodes() {
                applyFilters();
            }
            
            // Apply both type filters and search filter
            function applyFilters() {
                if (!originalNodes) {
                    originalNodes = nodes.get();
                    originalEdges = edges.get();
                }
                
                var nodeTypes = ['Domain', 'Subdomain', 'IP', 'CloudService', 'Technology', 'Vulnerability', 'Directory', 'Port', 'Service', 'Email', 'Person'];
                var visibleTypes = [];
                
                nodeTypes.forEach(function(type) {
                    var checkbox = document.getElementById('filter-' + type);
                    if (checkbox && checkbox.checked) {
                        visibleTypes.push(type);
                    }
                });
                
                // Update node visibility based on type and search
                var updatedNodes = originalNodes.map(function(node) {
                    var nodeGroup = node.group || 'Unknown';
                    // Handle IP_Cloud as IP
                    if (nodeGroup === 'IP_Cloud') nodeGroup = 'IP';
                    
                    var typeVisible = visibleTypes.includes(nodeGroup);
                    
                    // Apply search filter if query exists
                    var searchVisible = true;
                    if (searchQuery) {
                        var nodeLabel = (node.label || '').toLowerCase();
                        var nodeId = (node.id || '').toLowerCase();
                        searchVisible = nodeLabel.includes(searchQuery) || nodeId.includes(searchQuery);
                    }
                    
                    return {
                        id: node.id,
                        hidden: !(typeVisible && searchVisible)
                    };
                });
                
                // Apply updates
                nodes.update(updatedNodes);
                
                // Update edge visibility (hide edges connected to hidden nodes)
                var hiddenNodeIds = new Set();
                updatedNodes.forEach(function(node) {
                    if (node.hidden) {
                        hiddenNodeIds.add(node.id);
                    }
                });
                
                var updatedEdges = originalEdges.map(function(edge) {
                    var isHidden = hiddenNodeIds.has(edge.from) || hiddenNodeIds.has(edge.to);
                    return {
                        id: edge.id,
                        hidden: isHidden
                    };
                });
                
                edges.update(updatedEdges);
                
                // Focus on matched nodes if searching
                if (searchQuery) {
                    var visibleNodes = updatedNodes.filter(function(n) { return !n.hidden; });
                    if (visibleNodes.length > 0 && visibleNodes.length <= 5) {
                        network.fit({
                            nodes: visibleNodes.map(function(n) { return n.id; }),
                            animation: true
                        });
                    }
                }
                
                updateVisibleCount();
            }
            
            // Update visible count display
            function updateVisibleCount() {
                if (!originalNodes) return;
                
                var visibleNodes = nodes.get().filter(function(n) { return !n.hidden; });
                document.getElementById('visibleCount').textContent = visibleNodes.length + ' of ' + originalNodes.length + ' nodes';
            }
            
            // Show all nodes
            function showAllNodes() {
                var checkboxes = document.querySelectorAll('#filterSidebar input[type="checkbox"]');
                checkboxes.forEach(function(cb) { cb.checked = true; });
                document.getElementById('nodeSearch').value = '';
                searchQuery = '';
                document.getElementById('searchResults').textContent = '';
                filterNodes();
            }
            
            // Hide all nodes
            function hideAllNodes() {
                var checkboxes = document.querySelectorAll('#filterSidebar input[type="checkbox"]');
                checkboxes.forEach(function(cb) { cb.checked = false; });
                filterNodes();
            }
            
            // Layout configurations
            var hierarchicalLayout = {
                physics: {
                    hierarchicalRepulsion: {
                        centralGravity: 0.0,
                        springLength: 180,
                        springConstant: 0.008,
                        nodeDistance: 220,
                        damping: 0.12,
                        avoidOverlap: 1
                    },
                    maxVelocity: 40,
                    solver: 'hierarchicalRepulsion',
                    timestep: 0.4,
                    stabilization: { enabled: true, iterations: 250, updateInterval: 25 }
                },
                layout: {
                    hierarchical: {
                        enabled: true,
                        levelSeparation: 250,
                        nodeSpacing: 200,
                        treeSpacing: 300,
                        blockShifting: true,
                        edgeMinimization: true,
                        parentCentralization: true,
                        direction: 'UD',
                        sortMethod: 'directed'
                    }
                }
            };
            
            var forceLayout = {
                physics: {
                    forceAtlas2Based: {
                        gravitationalConstant: -100,
                        centralGravity: 0.008,
                        springLength: 250,
                        springConstant: 0.06,
                        avoidOverlap: 0.9
                    },
                    maxVelocity: 40,
                    solver: 'forceAtlas2Based',
                    timestep: 0.3,
                    stabilization: { enabled: true, iterations: 200, updateInterval: 25 }
                },
                layout: {
                    hierarchical: {
                        enabled: false
                    }
                }
            };
            
            var currentLayout = 'hierarchical';
            
            // Switch layout mode
            function setLayout(mode) {
                if (!network) return;
                
                currentLayout = mode;
                
                var btnHierarchical = document.getElementById('btn-hierarchical');
                var btnForce = document.getElementById('btn-force');
                
                if (mode === 'hierarchical') {
                    network.setOptions(hierarchicalLayout);
                    btnHierarchical.style.background = '#3b82f6';
                    btnHierarchical.style.color = 'white';
                    btnForce.style.background = '#45475a';
                    btnForce.style.color = '#cdd6f4';
                } else {
                    network.setOptions(forceLayout);
                    btnForce.style.background = '#3b82f6';
                    btnForce.style.color = 'white';
                    btnHierarchical.style.background = '#45475a';
                    btnHierarchical.style.color = '#cdd6f4';
                }
                
                // Re-stabilize the network
                network.stabilize(150);
            }
        </script>
        '''

        try:
            content = filepath.read_text(encoding="utf-8")
            
            # Insert filter sidebar before closing body tag
            content = content.replace("</body>", f"{filter_sidebar_html}{filter_script}</body>")
            
            filepath.write_text(content, encoding="utf-8")
            self.logger.debug("Injected filter sidebar JavaScript")
            
        except Exception as e:
            self.logger.warning(f"Could not inject filter sidebar: {e}")

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
