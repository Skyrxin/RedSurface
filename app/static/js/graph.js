/**
 * RedSurface — Interactive Attack Surface Graph
 * D3.js force-directed graph visualization
 */

class AttackSurfaceGraph {
    constructor(containerId, data) {
        this.container = document.getElementById(containerId);
        if (!this.container) return;

        this.data = data;
        this.width = this.container.clientWidth;
        this.height = 520;
        this.selectedNode = null;

        this.colors = {
            domain: '#ef4444',
            subdomain: '#3b82f6',
            email: '#22c55e',
            ip: '#f97316',
            technology: '#a855f7',
            contact: '#eab308',
            port: '#06b6d4',
            vulnerability: '#f43f5e',
            directory: '#8b5cf6',
            abuse_report: '#fb923c',
            hostname: '#0ea5e9',
            error: '#6b7280',
            aggregate: '#94a3b8',
        };

        this.sizes = {
            domain: 18,
            subdomain: 6,
            email: 8,
            ip: 10,
            technology: 10,
            contact: 8,
            port: 5,
            vulnerability: 7,
            hostname: 6,
            directory: 6,
            abuse_report: 7,
            error: 4,
            aggregate: 12,
        };

        this.init();
    }

    init() {
        // Clear the "Constructing neural graph..." loading placeholder (and any
        // prior render) before drawing — otherwise it stays overlaid on the graph.
        this.container.innerHTML = '';

        // Create SVG
        this.svg = d3.select(this.container)
            .append('svg')
            .attr('width', this.width)
            .attr('height', this.height)
            .attr('viewBox', [0, 0, this.width, this.height]);

        // Defs for glow filter
        const defs = this.svg.append('defs');
        const filter = defs.append('filter').attr('id', 'glow');
        filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
        const merge = filter.append('feMerge');
        merge.append('feMergeNode').attr('in', 'coloredBlur');
        merge.append('feMergeNode').attr('in', 'SourceGraphic');

        // Background
        this.svg.append('rect')
            .attr('width', this.width)
            .attr('height', this.height)
            .attr('fill', 'transparent');

        // Container group for zoom
        this.g = this.svg.append('g');

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                this.g.attr('transform', event.transform);
            });
        this.svg.call(zoom);

        // Build graph
        this.buildGraph();
        this.render();
        this.createLegend();
    }

    buildGraph() {
        const nodes = [];
        const links = [];
        const nodeMap = new Map();

        // Central domain node
        const target = this.data.target;
        const domainId = `domain:${target}`;
        nodes.push({
            id: domainId,
            label: target,
            type: 'domain',
            group: 'domain',
        });
        nodeMap.set(domainId, true);

        // Process results
        for (const result of this.data.results) {
            const type = result.result_type || 'unknown';
            const value = result.value || '';
            const module = result.module_name || '';
            const nodeId = result.id || `${type}:${value}`;

            if (nodeMap.has(nodeId)) continue;
            nodeMap.set(nodeId, true);

            nodes.push({
                id: nodeId,
                label: this.truncateLabel(value),
                fullLabel: value,
                type: type,
                group: type,
                module: module,
                metadata: result.metadata || {}
            });

            // Link to parent or central domain
            let sourceId = domainId;
            if (result.parent_value) {
                // Determine parent type (heuristic: technology links to subdomain, vulnerability links to technology)
                let parentType = 'subdomain';
                if (type === 'vulnerability') parentType = 'technology';
                else if (type === 'port' || type === 'technology' || type === 'waf' || type === 'directory') parentType = 'subdomain';
                else if (type === 'subdomain') parentType = 'domain';
                
                const possibleParentId = `${parentType}:${result.parent_value}`;
                // Only link to parent if it exists in our node map, otherwise fallback to domain
                if (nodeMap.has(possibleParentId)) {
                    sourceId = possibleParentId;
                } else {
                    // Try without type prefix if we can't find it
                    // Search nodes for any node with fullLabel === result.parent_value
                    const parentNode = nodes.find(n => n.fullLabel === result.parent_value);
                    if (parentNode) {
                        sourceId = parentNode.id;
                    }
                }
            }

            links.push({
                source: sourceId,
                target: nodeId,
                type: type,
            });
        }

        this.nodes = nodes;
        this.links = links;
    }

    truncateLabel(text) {
        if (text.length > 30) {
            return text.substring(0, 27) + '…';
        }
        return text;
    }

    render() {
        const simulation = d3.forceSimulation(this.nodes)
            .force('link', d3.forceLink(this.links).id(d => d.id).distance(d => {
                if (d.type === 'subdomain') return 80;
                if (d.type === 'aggregate') return 150;
                return 120;
            }))
            .force('charge', d3.forceManyBody().strength(d => {
                if (d.type === 'domain') return -400;
                if (d.type === 'aggregate') return -200;
                return -60;
            }))
            .force('center', d3.forceCenter(this.width / 2, this.height / 2))
            .force('collision', d3.forceCollide().radius(d => (this.sizes[d.type] || 6) + 3));

        // Links
        const link = this.g.append('g')
            .selectAll('line')
            .data(this.links)
            .join('line')
            .attr('stroke', d => {
                const c = this.colors[d.type] || '#374151';
                return c;
            })
            .attr('stroke-opacity', 0.2)
            .attr('stroke-width', 0.5);

        // Nodes
        const node = this.g.append('g')
            .selectAll('circle')
            .data(this.nodes)
            .join('circle')
            .attr('r', d => this.sizes[d.type] || 6)
            .attr('fill', d => this.colors[d.type] || '#6b7280')
            .attr('stroke', d => {
                if (d.type === 'domain') return '#fff';
                if (d.type === 'aggregate') return 'rgba(255, 255, 255, 0.5)';
                return 'none';
            })
            .attr('stroke-width', d => d.type === 'domain' ? 2 : (d.type === 'aggregate' ? 1 : 0))
            .attr('cursor', 'pointer')
            .style('filter', d => d.type === 'domain' ? 'url(#glow)' : 'none')
            .call(this.drag(simulation));

        // Labels (domain + aggregates)
        const label = this.g.append('g')
            .selectAll('text')
            .data(this.nodes.filter(d => d.type === 'domain' || d.type === 'aggregate'))
            .join('text')
            .attr('text-anchor', 'middle')
            .attr('dy', d => -(this.sizes[d.type] || 6) - 6)
            .attr('fill', '#f1f5f9')
            .attr('font-size', d => d.type === 'domain' ? '11px' : '9px')
            .attr('font-weight', '600')
            .attr('font-family', 'Inter, sans-serif')
            .text(d => d.label);

        // Tooltip
        const tooltip = d3.select(this.container)
            .append('div')
            .attr('class', 'graph-tooltip')
            .style('display', 'none');

        node.on('mouseover', (event, d) => {
            let tooltipContent = `
                <div class="tooltip-type">${d.type}</div>
                <div class="tooltip-value">${d.fullLabel || d.label}</div>
            `;
            
            if (d.type === 'aggregate' && d.metadata) {
                tooltipContent += `<div class="tooltip-module">Contains ${d.metadata.count} ${d.metadata.original_type}s</div>`;
            } else if (d.module) {
                tooltipContent += `<div class="tooltip-module">via ${d.module}</div>`;
            }

            tooltip
                .style('display', 'block')
                .html(tooltipContent)
                .style('left', (event.offsetX + 15) + 'px')
                .style('top', (event.offsetY - 10) + 'px');

            // Highlight connected
            link.attr('stroke-opacity', l =>
                l.source.id === d.id || l.target.id === d.id ? 0.8 : 0.05
            ).attr('stroke-width', l =>
                l.source.id === d.id || l.target.id === d.id ? 1.5 : 0.5
            );

            node.attr('opacity', n => {
                if (n.id === d.id) return 1;
                const connected = this.links.some(l =>
                    (l.source.id === d.id && l.target.id === n.id) ||
                    (l.target.id === d.id && l.source.id === n.id)
                );
                return connected ? 1 : 0.15;
            });
        });

        node.on('mouseout', () => {
            tooltip.style('display', 'none');
            link.attr('stroke-opacity', 0.2).attr('stroke-width', 0.5);
            node.attr('opacity', 1);
        });

        // Simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);

            label
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        });
    }

    drag(simulation) {
        return d3.drag()
            .on('start', (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on('drag', (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on('end', (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            });
    }

    createLegend() {
        // Collect types present in data
        const types = [...new Set(this.nodes.map(n => n.type))];

        const legend = d3.select(this.container)
            .append('div')
            .attr('class', 'graph-legend');

        types.forEach(type => {
            const count = this.nodes.filter(n => n.type === type).length;
            const item = legend.append('div').attr('class', 'legend-item');
            item.append('span')
                .attr('class', 'legend-dot')
                .style('background', this.colors[type] || '#6b7280');
            item.append('span')
                .attr('class', 'legend-label')
                .text(`${type} (${count})`);
        });
    }
}

// Initialize when graph data is available
function initAttackGraph(containerId, scanId) {
    fetch(`/api/scans/${scanId}/graph`)
        .then(r => r.json())
        .then(data => {
            if (data.results && data.results.length > 0) {
                new AttackSurfaceGraph(containerId, data);
            } else {
                document.getElementById(containerId).innerHTML =
                    '<div class="graph-empty" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--text-muted);">No graph data for this scan.</div>';
            }
        })
        .catch(err => {
            console.error('Graph error:', err);
            document.getElementById(containerId).innerHTML =
                '<div class="graph-empty">Failed to load graph data.</div>';
        });
}
