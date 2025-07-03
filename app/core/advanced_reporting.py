# app/core/advanced_reporting.py
from datetime import datetime, timedelta
from pathlib import Path
import json
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from app.core.logger import logger
from app.core.config import config
from app.core.validators import InputValidator

class AdvancedReporting:
    """Advanced reporting engine with comprehensive analysis and multiple output formats"""
    
    def __init__(self):
        self.report_templates = {
            'executive': 'Executive Summary Report',
            'technical': 'Technical Detailed Report', 
            'compliance': 'Compliance Assessment Report',
            'vulnerability': 'Vulnerability Assessment Report',
            'comparison': 'Scan Comparison Report'
        }
        
        self.risk_matrix = {
            'critical': {'score': 10, 'color': '#8B0000', 'priority': 1},
            'high': {'score': 7, 'color': '#FF4500', 'priority': 2},
            'medium': {'score': 5, 'color': '#FFA500', 'priority': 3},
            'low': {'score': 3, 'color': '#32CD32', 'priority': 4},
            'info': {'score': 1, 'color': '#4169E1', 'priority': 5}
        }
        
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom PDF styles"""
        if not REPORTLAB_AVAILABLE:
            return
            
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontSize=28,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveHeader',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=15,
            textColor=colors.darkred,
            borderWidth=2,
            borderColor=colors.darkred,
            borderPadding=8
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=12,
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=12,
            leftIndent=20
        ))
    
    def generate_comprehensive_report(self, scan_data: Dict, report_type: str = 'technical', 
                                   output_format: str = 'pdf', custom_template: Dict = None) -> Tuple[bool, str, str]:
        """Generate comprehensive report with advanced analysis"""
        try:
            # Analyze scan data
            analysis = self._perform_comprehensive_analysis(scan_data)
            
            # Generate report based on format
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown')
            safe_target = InputValidator.sanitize_filename(target)
            
            if output_format.lower() == 'pdf' and REPORTLAB_AVAILABLE:
                filename = f"advanced_report_{safe_target}_{timestamp}.pdf"
                return self._generate_pdf_report(analysis, report_type, filename, custom_template)
            elif output_format.lower() == 'html':
                filename = f"advanced_report_{safe_target}_{timestamp}.html"
                return self._generate_html_report(analysis, report_type, filename, custom_template)
            elif output_format.lower() == 'json':
                filename = f"advanced_report_{safe_target}_{timestamp}.json"
                return self._generate_json_report(analysis, report_type, filename)
            else:
                return False, "", f"Unsupported format: {output_format}"
                
        except Exception as e:
            logger.error(f"Advanced report generation failed: {str(e)}")
            return False, "", f"Report generation failed: {str(e)}"
    
    def _perform_comprehensive_analysis(self, scan_data: Dict) -> Dict:
        """Perform comprehensive analysis of scan data"""
        analysis = {
            'metadata': self._extract_metadata(scan_data),
            'risk_assessment': self._assess_risks(scan_data),
            'findings_summary': self._summarize_findings(scan_data),
            'trend_analysis': self._analyze_trends(scan_data),
            'recommendations': self._generate_recommendations(scan_data),
            'compliance_check': self._check_compliance(scan_data),
            'attack_surface': self._analyze_attack_surface(scan_data),
            'statistics': self._calculate_statistics(scan_data)
        }
        return analysis
    
    def _extract_metadata(self, scan_data: Dict) -> Dict:
        """Extract and enhance metadata"""
        return {
            'target': scan_data.get('target', 'Unknown'),
            'scan_type': scan_data.get('scan_type', 'Unknown'),
            'timestamp': scan_data.get('timestamp', datetime.now().isoformat()),
            'duration': scan_data.get('duration', 'Unknown'),
            'tool_version': 'Hackulator Advanced v2.0',
            'report_id': hashlib.md5(f"{scan_data.get('target', '')}{datetime.now()}".encode()).hexdigest()[:8],
            'total_findings': len(scan_data.get('results', {}))
        }
    
    def _assess_risks(self, scan_data: Dict) -> Dict:
        """Comprehensive risk assessment"""
        risks = defaultdict(list)
        risk_score = 0
        
        results = scan_data.get('results', {})
        
        # DNS-specific risk assessment
        if scan_data.get('scan_type') == 'dns_enum':
            subdomain_count = len(results)
            
            if subdomain_count > 100:
                risks['critical'].append(f"Excessive subdomain exposure ({subdomain_count} subdomains)")
                risk_score += 10
            elif subdomain_count > 50:
                risks['high'].append(f"High subdomain exposure ({subdomain_count} subdomains)")
                risk_score += 7
            
            # Check for sensitive subdomains
            sensitive_patterns = ['admin', 'test', 'dev', 'staging', 'backup', 'api', 'internal', 'vpn']
            for domain in results.keys():
                for pattern in sensitive_patterns:
                    if pattern in domain.lower():
                        risks['high'].append(f"Sensitive subdomain exposed: {domain}")
                        risk_score += 5
        
        # Port scan risk assessment
        elif scan_data.get('scan_type') == 'port_scan':
            open_ports = scan_data.get('open_ports', [])
            dangerous_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3389]
            
            for port in open_ports:
                if port in dangerous_ports:
                    risks['medium'].append(f"Potentially risky port open: {port}")
                    risk_score += 3
        
        return {
            'breakdown': dict(risks),
            'total_score': risk_score,
            'risk_level': self._calculate_risk_level(risk_score),
            'risk_factors': self._identify_risk_factors(scan_data)
        }
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calculate overall risk level"""
        if score >= 20:
            return 'critical'
        elif score >= 15:
            return 'high'
        elif score >= 10:
            return 'medium'
        elif score >= 5:
            return 'low'
        else:
            return 'info'
    
    def _summarize_findings(self, scan_data: Dict) -> Dict:
        """Summarize key findings"""
        results = scan_data.get('results', {})
        
        summary = {
            'total_items': len(results),
            'categories': defaultdict(int),
            'top_findings': [],
            'notable_patterns': []
        }
        
        # Categorize findings
        if scan_data.get('scan_type') == 'dns_enum':
            for domain, records in results.items():
                for record_type, values in records.items():
                    summary['categories'][record_type] += len(values) if isinstance(values, list) else 1
            
            # Identify patterns
            domains = list(results.keys())
            if len(domains) > 10:
                common_prefixes = self._find_common_patterns(domains)
                summary['notable_patterns'] = common_prefixes[:5]
        
        return summary
    
    def _analyze_trends(self, scan_data: Dict) -> Dict:
        """Analyze trends and patterns"""
        return {
            'scan_frequency': 'First scan',  # Would be enhanced with historical data
            'change_detection': 'No previous data',
            'growth_patterns': [],
            'seasonal_trends': []
        }
    
    def _generate_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if scan_data.get('scan_type') == 'dns_enum':
            subdomain_count = len(scan_data.get('results', {}))
            
            if subdomain_count > 50:
                recommendations.append({
                    'priority': 'high',
                    'category': 'Attack Surface Reduction',
                    'title': 'Reduce Subdomain Exposure',
                    'description': 'Consider consolidating or removing unnecessary subdomains',
                    'impact': 'Reduces attack surface and potential entry points'
                })
            
            recommendations.append({
                'priority': 'medium',
                'category': 'Monitoring',
                'title': 'Implement DNS Monitoring',
                'description': 'Set up monitoring for new subdomain creation',
                'impact': 'Early detection of unauthorized DNS changes'
            })
        
        # Generic recommendations
        recommendations.extend([
            {
                'priority': 'low',
                'category': 'Documentation',
                'title': 'Document Findings',
                'description': 'Maintain inventory of discovered assets',
                'impact': 'Improved asset management and security posture'
            }
        ])
        
        return recommendations
    
    def _check_compliance(self, scan_data: Dict) -> Dict:
        """Check against common compliance frameworks"""
        return {
            'frameworks': ['OWASP', 'NIST', 'ISO27001'],
            'compliance_score': 75,  # Placeholder
            'gaps': [
                'Asset inventory incomplete',
                'Monitoring gaps identified'
            ],
            'recommendations': [
                'Implement comprehensive asset discovery',
                'Enhance monitoring capabilities'
            ]
        }
    
    def _analyze_attack_surface(self, scan_data: Dict) -> Dict:
        """Analyze attack surface"""
        surface = {
            'exposed_services': [],
            'entry_points': [],
            'attack_vectors': [],
            'surface_score': 0
        }
        
        if scan_data.get('scan_type') == 'dns_enum':
            subdomain_count = len(scan_data.get('results', {}))
            surface['entry_points'] = [f"{subdomain_count} subdomains discovered"]
            surface['surface_score'] = min(subdomain_count * 2, 100)
        
        return surface
    
    def _calculate_statistics(self, scan_data: Dict) -> Dict:
        """Calculate detailed statistics"""
        results = scan_data.get('results', {})
        
        stats = {
            'total_records': 0,
            'record_types': defaultdict(int),
            'distribution': {},
            'coverage_metrics': {}
        }
        
        if scan_data.get('scan_type') == 'dns_enum':
            for domain, records in results.items():
                for record_type, values in records.items():
                    count = len(values) if isinstance(values, list) else 1
                    stats['total_records'] += count
                    stats['record_types'][record_type] += count
        
        return stats
    
    def _generate_pdf_report(self, analysis: Dict, report_type: str, filename: str, 
                           custom_template: Dict = None) -> Tuple[bool, str, str]:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            return False, "", "ReportLab not available for PDF generation"
        
        try:
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            filepath = export_dir / filename
            
            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            story = []
            
            # Title page
            story.append(Paragraph("Advanced Security Assessment Report", self.styles['ReportTitle']))
            story.append(Spacer(1, 30))
            
            # Executive summary
            story.append(Paragraph("Executive Summary", self.styles['ExecutiveHeader']))
            story.append(Paragraph(self._generate_executive_text(analysis), self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Risk assessment
            self._add_risk_section(story, analysis['risk_assessment'])
            
            # Findings
            self._add_findings_section(story, analysis['findings_summary'])
            
            # Recommendations
            self._add_recommendations_section(story, analysis['recommendations'])
            
            # Statistics
            if report_type == 'technical':
                self._add_statistics_section(story, analysis['statistics'])
            
            doc.build(story)
            return True, str(filepath), "Advanced PDF report generated successfully"
            
        except Exception as e:
            return False, "", f"PDF generation failed: {str(e)}"
    
    def _generate_html_report(self, analysis: Dict, report_type: str, filename: str,
                            custom_template: Dict = None) -> Tuple[bool, str, str]:
        """Generate HTML report"""
        try:
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            filepath = export_dir / filename
            
            html_content = self._build_html_content(analysis, report_type)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True, str(filepath), "Advanced HTML report generated successfully"
            
        except Exception as e:
            return False, "", f"HTML generation failed: {str(e)}"
    
    def _generate_json_report(self, analysis: Dict, report_type: str, filename: str) -> Tuple[bool, str, str]:
        """Generate JSON report"""
        try:
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            filepath = export_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, default=str)
            
            return True, str(filepath), "Advanced JSON report generated successfully"
            
        except Exception as e:
            return False, "", f"JSON generation failed: {str(e)}"
    
    def _build_html_content(self, analysis: Dict, report_type: str) -> str:
        """Build HTML report content"""
        metadata = analysis['metadata']
        risk_assessment = analysis['risk_assessment']
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Advanced Security Report - {metadata['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
                .risk-critical {{ color: #e74c3c; font-weight: bold; }}
                .risk-high {{ color: #f39c12; font-weight: bold; }}
                .risk-medium {{ color: #f1c40f; font-weight: bold; }}
                .risk-low {{ color: #27ae60; font-weight: bold; }}
                .recommendation {{ background: #ecf0f1; padding: 10px; margin: 10px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Advanced Security Assessment Report</h1>
                <p>Target: {metadata['target']} | Generated: {metadata['timestamp']}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>{self._generate_executive_text(analysis)}</p>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <p>Overall Risk Level: <span class="risk-{risk_assessment['risk_level']}">{risk_assessment['risk_level'].upper()}</span></p>
                <p>Risk Score: {risk_assessment['total_score']}/100</p>
            </div>
            
            <div class="section">
                <h2>Key Findings</h2>
                <ul>
        """
        
        # Add findings
        for risk_level, findings in risk_assessment['breakdown'].items():
            for finding in findings:
                html += f'<li class="risk-{risk_level}">[{risk_level.upper()}] {finding}</li>'
        
        html += """
                </ul>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
        """
        
        # Add recommendations
        for rec in analysis['recommendations']:
            html += f"""
                <div class="recommendation">
                    <h4>{rec['title']} ({rec['priority'].upper()} Priority)</h4>
                    <p><strong>Category:</strong> {rec['category']}</p>
                    <p><strong>Description:</strong> {rec['description']}</p>
                    <p><strong>Impact:</strong> {rec['impact']}</p>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_executive_text(self, analysis: Dict) -> str:
        """Generate executive summary text"""
        metadata = analysis['metadata']
        risk_assessment = analysis['risk_assessment']
        
        text = f"This comprehensive security assessment of {metadata['target']} identified "
        text += f"{metadata['total_findings']} findings with an overall risk level of "
        text += f"{risk_assessment['risk_level'].upper()}. "
        
        if risk_assessment['total_score'] > 15:
            text += "Immediate attention is required to address critical security issues. "
        elif risk_assessment['total_score'] > 10:
            text += "Several security concerns require prompt attention. "
        else:
            text += "The security posture is generally acceptable with minor improvements needed. "
        
        return text
    
    def _add_risk_section(self, story, risk_assessment):
        """Add risk assessment section to PDF"""
        story.append(Paragraph("Risk Assessment", self.styles['ExecutiveHeader']))
        story.append(Paragraph(f"Overall Risk Level: {risk_assessment['risk_level'].upper()}", 
                              self.styles['Normal']))
        story.append(Paragraph(f"Risk Score: {risk_assessment['total_score']}/100", 
                              self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Risk breakdown
        for risk_level, findings in risk_assessment['breakdown'].items():
            if findings:
                story.append(Paragraph(f"{risk_level.upper()} Risk Items:", 
                                     self.styles['Heading3']))
                for finding in findings:
                    story.append(Paragraph(f"• {finding}", self.styles['Normal']))
                story.append(Spacer(1, 10))
    
    def _add_findings_section(self, story, findings_summary):
        """Add findings section to PDF"""
        story.append(Paragraph("Key Findings", self.styles['ExecutiveHeader']))
        story.append(Paragraph(f"Total Items Discovered: {findings_summary['total_items']}", 
                              self.styles['Normal']))
        
        if findings_summary['categories']:
            story.append(Paragraph("Categories:", self.styles['Heading3']))
            for category, count in findings_summary['categories'].items():
                story.append(Paragraph(f"• {category}: {count}", self.styles['Normal']))
        
        story.append(Spacer(1, 15))
    
    def _add_recommendations_section(self, story, recommendations):
        """Add recommendations section to PDF"""
        story.append(Paragraph("Recommendations", self.styles['ExecutiveHeader']))
        
        for rec in recommendations:
            story.append(Paragraph(f"{rec['title']} ({rec['priority'].upper()} Priority)", 
                                 self.styles['Heading3']))
            story.append(Paragraph(f"Category: {rec['category']}", self.styles['Normal']))
            story.append(Paragraph(f"Description: {rec['description']}", self.styles['Normal']))
            story.append(Paragraph(f"Impact: {rec['impact']}", self.styles['Normal']))
            story.append(Spacer(1, 10))
    
    def _add_statistics_section(self, story, statistics):
        """Add statistics section to PDF"""
        story.append(PageBreak())
        story.append(Paragraph("Technical Statistics", self.styles['ExecutiveHeader']))
        story.append(Paragraph(f"Total Records: {statistics['total_records']}", 
                              self.styles['Normal']))
        
        if statistics['record_types']:
            story.append(Paragraph("Record Type Distribution:", self.styles['Heading3']))
            for record_type, count in statistics['record_types'].items():
                story.append(Paragraph(f"• {record_type}: {count}", self.styles['Normal']))
    
    def _find_common_patterns(self, domains: List[str]) -> List[str]:
        """Find common patterns in domain names"""
        patterns = []
        prefixes = defaultdict(int)
        
        for domain in domains:
            parts = domain.split('.')
            if len(parts) > 2:
                prefix = parts[0]
                prefixes[prefix] += 1
        
        # Return most common prefixes
        return [prefix for prefix, count in Counter(prefixes).most_common(5) if count > 1]
    
    def _identify_risk_factors(self, scan_data: Dict) -> List[str]:
        """Identify specific risk factors"""
        factors = []
        
        if scan_data.get('scan_type') == 'dns_enum':
            subdomain_count = len(scan_data.get('results', {}))
            if subdomain_count > 20:
                factors.append("Large attack surface due to numerous subdomains")
            
            # Check for wildcard DNS
            if scan_data.get('wildcard_detected'):
                factors.append("Wildcard DNS configuration detected")
        
        return factors

# Global instance
advanced_reporting = AdvancedReporting()