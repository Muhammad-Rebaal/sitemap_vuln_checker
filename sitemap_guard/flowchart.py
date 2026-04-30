from typing import List, Dict, Any
from urllib.parse import urlparse
from pathlib import Path
import json
import structlog

logger = structlog.get_logger()

def generate_flowchart(live_targets: List[Dict[str, Any]], nuclei_findings: List[Dict[str, Any]], header_findings: List[Dict[str, Any]], threat_findings: List[Dict[str, Any]], output_path: str):
    """
    Generate an ultra-premium interactive security analysis flowchart.
    Deduplicates findings and includes detailed vulnerability descriptions.
    """
    # 1. Map data & Deduplicate findings
    findings_by_url = {}
    unique_findings = {} # (url, template_id) -> finding_data
    
    for f in nuclei_findings:
        url = f.get("url", "").rstrip('/')
        tid = f.get("template-id", "unknown")
        key = (url, tid)
        
        if key not in unique_findings:
            unique_findings[key] = f
        else:
            existing = unique_findings[key]
            m1 = existing.get("matcher-name")
            m2 = f.get("matcher-name")
            if m1 and m2 and m1 != m2:
                existing["matcher-name"] = f"{m1}, {m2}"

    # Also add header findings
    for f in header_findings:
        url = f.get("url", "").rstrip('/')
        name = f.get("name", "Header Issue")
        key = (url, f"header_{name}")
        unique_findings[key] = {
            "info": {
                "name": name,
                "severity": f.get("severity", "info"),
                "description": f.get("details", name)
            },
            "template-id": f.get("type", "header"),
            "url": url
        }
        
    # Also add threat findings
    for f in threat_findings:
        url = f.get("url", "").rstrip('/')
        name = f.get("type", "Threat")
        key = (url, f"threat_{name}")
        unique_findings[key] = {
            "info": {
                "name": "Local Threat Feed Hit",
                "severity": f.get("severity", "high"),
                "description": f"URL matched local threat feed: {f.get('source')}"
            },
            "template-id": "threat-feed",
            "url": url
        }

    for (url, tid), f in unique_findings.items():
        if url not in findings_by_url: findings_by_url[url] = []
        findings_by_url[url].append(f)
    
    tech_by_url = {t.get("url", "").rstrip('/'): t for t in live_targets}
    
    severity_colors = {
        "critical": "#ff1744", "high": "#ff6d00", "medium": "#ffd600",
        "low": "#00e5ff", "info": "#58a6ff", "unknown": "#8b949e"
    }
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}

    # 2. Build Tree
    tree = {"name": "Security Perimeter", "itemStyle": {"color": "#58a6ff"}, "children": []}
    nodes_registry = {"Root": tree}
    
    all_urls = set(tech_by_url.keys()) | set(findings_by_url.keys())
    if not all_urls and live_targets:
        all_urls = {t.get("url", "").rstrip('/') for t in live_targets}

    for url in all_urls:
        if not url: continue
        parsed = urlparse(url)
        domain = parsed.netloc or url
        
        if domain not in nodes_registry:
            domain_node = {"name": domain, "itemStyle": {"color": "#8b949e"}, "children": []}
            tree["children"].append(domain_node)
            nodes_registry[domain] = domain_node
            
        path_parts = [p for p in parsed.path.split('/') if p]
        current_node = nodes_registry[domain]
        
        path_so_far = domain
        for i, part in enumerate(path_parts):
            path_so_far += "/" + part
            if path_so_far not in nodes_registry:
                new_node = {"name": part, "children": []}
                current_node["children"].append(new_node)
                nodes_registry[path_so_far] = new_node
            current_node = nodes_registry[path_so_far]

        # Get Analysis Data
        target_data = tech_by_url.get(url, {})
        vulns = findings_by_url.get(url, [])
        
        max_sev = "info"
        max_rank = 0
        vuln_nodes = []
        for v in vulns:
            info = v.get("info", {})
            sev = info.get("severity", "info").lower()
            name = info.get("name", "Finding")
            matcher = v.get("matcher-name", "")
            desc = info.get("description", "No description available.")
            
            vuln_nodes.append({
                "name": f"[{sev.upper()}] {name}",
                "itemStyle": {"color": severity_colors.get(sev, "#8b949e")},
                "tooltip_data": {
                    "type": "vulnerability",
                    "name": name,
                    "severity": sev,
                    "description": desc,
                    "matcher": matcher,
                    "template": v.get("template-id"),
                    "url": url
                }
            })
            if severity_rank.get(sev, -1) > max_rank:
                max_rank = severity_rank[sev]
                max_sev = sev
        
        tech_list = target_data.get("tech", [])
        tech_nodes = [{"name": t, "itemStyle": {"color": "#00e676"}} for t in tech_list]
        
        analysis_hub = {"name": "Security Insights", "children": [], "itemStyle": {"color": severity_colors[max_sev]}}
        if vuln_nodes:
            analysis_hub["children"].append({
                "name": f"Vulnerabilities ({len(vuln_nodes)})", 
                "children": sorted(vuln_nodes, key=lambda x: severity_rank.get(x["tooltip_data"]["severity"], 0), reverse=True),
                "itemStyle": {"color": severity_colors[max_sev]}
            })
        if tech_nodes:
            analysis_hub["children"].append({"name": "Tech Stack", "children": tech_nodes, "itemStyle": {"color": "#00e676"}})
        
        if analysis_hub["children"]:
            current_node["children"].append(analysis_hub)
            current_node["itemStyle"] = {"color": severity_colors[max_sev], "borderColor": severity_colors[max_sev], "borderWidth": 2}
            current_node["name"] = f"{current_node['name']} ({len(vuln_nodes)} Findings)"

    # 3. HTML Generation
    echarts_js = ""
    try:
        js_path = Path(__file__).parent / "templates" / "echarts.min.js"
        if js_path.exists(): echarts_js = js_path.read_text(encoding="utf-8")
        else:
            # Fallback to CDN if missing
            echarts_js = ""
    except Exception: pass
    
    script_tag = f'<script type="text/javascript">{echarts_js}</script>' if echarts_js else '<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>'

    tree_json = json.dumps(tree)
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SiteMap Guard - Intelligent Analysis</title>
    {script_tag}
    <style>
        body {{ margin: 0; padding: 0; background-color: #010409; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; overflow: hidden; }}
        #main {{ width: 100vw; height: 100vh; }}
        .overlay {{ position: absolute; top: 30px; left: 30px; z-index: 10; pointer-events: none; }}
        .glass {{ background: rgba(13, 17, 23, 0.85); backdrop-filter: blur(12px); border: 1px solid #30363d; padding: 20px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }}
    </style>
</head>
<body>
    <div class="overlay glass">
        <h1 style="margin:0; font-size: 28px; background: linear-gradient(to right, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">SiteMap Guard Intelligence</h1>
        <p style="color: #8b949e; margin: 5px 0 15px 0;">Recursive Vulnerability & Asset Mapping</p>
        <div style="display:flex; gap: 15px; font-size: 11px;">
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#ff1744; margin-right:6px;"></div> Critical</div>
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#ff6d00; margin-right:6px;"></div> High</div>
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#ffd600; margin-right:6px;"></div> Medium</div>
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#00e5ff; margin-right:6px;"></div> Low</div>
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#58a6ff; margin-right:6px;"></div> Info</div>
            <div style="display:flex; align-items:center;"><div style="width:10px; height:10px; border-radius:50%; background:#00e676; margin-right:6px;"></div> Technology</div>
        </div>
    </div>
    <div id="main"></div>
    <script type="text/javascript">
        var chartDom = document.getElementById('main');
        var myChart = echarts.init(chartDom, 'dark');
        var data = {tree_json};
        
        myChart.setOption({{
            tooltip: {{ 
                trigger: 'item', 
                triggerOn: 'mousemove',
                backgroundColor: '#161b22',
                borderColor: '#30363d',
                textStyle: {{ color: '#e6edf3', fontSize: 12 }},
                formatter: function(params) {{
                    var d = params.data.tooltip_data;
                    if (!d) return params.name;
                    if (d.type === 'vulnerability') {{
                        var res = '<div style="padding:10px; max-width:400px; white-space: normal;">';
                        res += '<b style="color:#58a6ff; font-size:14px;">' + d.name + '</b>';
                        res += '<span style="float:right; margin-left:10px; padding:2px 6px; border-radius:4px; background:#30363d; font-size:10px;">' + d.severity.toUpperCase() + '</span><br/>';
                        res += '<hr style="border:0; border-top:1px solid #30363d; margin:8px 0;"/>';
                        res += '<p style="color:#8b949e; line-height:1.4;">' + d.description + '</p>';
                        if (d.matcher) res += '<b>Matched:</b> <code style="color:#ffd600">' + d.matcher + '</code><br/>';
                        res += '<b>Template:</b> <code style="color:#bc8cff">' + d.template + '</code><br/>';
                        res += '</div>';
                        return res;
                    }}
                    return params.name;
                }}
            }},
            series: [{{
                type: 'tree',
                data: [data],
                top: '5%', left: '15%', bottom: '5%', right: '25%',
                symbolSize: 14,
                initialTreeDepth: 2,
                label: {{
                    position: 'left',
                    verticalAlign: 'middle',
                    align: 'right',
                    fontSize: 13,
                    color: '#e6edf3',
                    distance: 12
                }},
                leaves: {{
                    label: {{ position: 'right', align: 'left', verticalAlign: 'middle' }}
                }},
                lineStyle: {{ color: '#30363d', width: 2, curveness: 0.5 }},
                itemStyle: {{ borderWidth: 2, borderColor: '#0d1117' }},
                emphasis: {{ focus: 'descendant', lineStyle: {{ width: 4, color: '#58a6ff' }} }},
                expandAndCollapse: true,
                animationDuration: 1000
            }}]
        }});
        window.addEventListener('resize', function() {{ myChart.resize(); }});
    </script>
</body>
</html>
"""
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
