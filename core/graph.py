"""
Attack Surface Intelligence Graph using NetworkX.
"""

from typing import Optional
import networkx as nx

from .target import Target


class AttackGraph:
    """
    Builds and manages the Attack Surface Intelligence Graph.
    
    Node Types: Domain, Subdomain, IP, CloudService, Technology, Vulnerability
    Edge Types: RESOLVES_TO, HOSTED_ON, EXPOSES, AFFECTED_BY
    """

    def __init__(self) -> None:
        """Initialize an empty directed graph."""
        self.graph: nx.DiGraph = nx.DiGraph()

    def build_from_target(self, target: Target) -> None:
        """
        Construct the graph from a Target's discovered data.

        Args:
            target: Target instance with reconnaissance data
        """
        # Add root domain node
        self._add_node(target.domain, node_type="Domain")

        # Add subdomains and link to domain
        for subdomain in target.subdomains:
            self._add_node(subdomain, node_type="Subdomain")
            self._add_edge(target.domain, subdomain, edge_type="HAS_SUBDOMAIN")

        # Add IPs and RESOLVES_TO edges
        for hostname, ips in target.ips.items():
            for ip in ips:
                self._add_node(ip, node_type="IP")
                self._add_edge(hostname, ip, edge_type="RESOLVES_TO")

        # Add cloud services and HOSTED_ON edges
        for ip, provider in target.cloud_services.items():
            cloud_node = f"{provider}"
            self._add_node(cloud_node, node_type="CloudService")
            self._add_edge(ip, cloud_node, edge_type="HOSTED_ON")

        # Add technologies and EXPOSES edges
        for host, techs in target.technologies.items():
            for tech in techs:
                self._add_node(tech, node_type="Technology")
                self._add_edge(host, tech, edge_type="EXPOSES")

        # Add vulnerabilities and AFFECTED_BY edges
        for tech, cves in target.vulnerabilities.items():
            for cve in cves:
                self._add_node(cve, node_type="Vulnerability")
                self._add_edge(tech, cve, edge_type="AFFECTED_BY")

    def _add_node(self, node_id: str, node_type: str) -> None:
        """Add a node with its type attribute."""
        self.graph.add_node(node_id, node_type=node_type)

    def _add_edge(self, source: str, target: str, edge_type: str) -> None:
        """Add an edge with its type attribute."""
        self.graph.add_edge(source, target, edge_type=edge_type)

    @property
    def node_count(self) -> int:
        """Return the number of nodes in the graph."""
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Return the number of edges in the graph."""
        return self.graph.number_of_edges()

    def get_networkx_graph(self) -> nx.DiGraph:
        """Return the underlying NetworkX graph."""
        return self.graph
