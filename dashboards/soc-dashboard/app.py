#!/usr/bin/env python3
"""
app.py
AI-Powered Threat Detection System
SOC Dashboard for security analysts
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="SOC Dashboard - AI-Powered Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }
    .severity-critical {
        color: #ff4b4b;
        font-weight: bold;
    }
    .severity-high {
        color: #ff8c00;
        font-weight: bold;
    }
    .severity-medium {
        color: #ffd700;
        font-weight: bold;
    }
    .severity-low {
        color: #90ee90;
        font-weight: bold;
    }
    .severity-info {
        color: #87ceeb;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


class SOCDashboard:
    """SOC Dashboard for threat detection visualization"""
    
    def __init__(self):
        """Initialize dashboard"""
        self.data_dir = Path("data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Load mock data if real data not available
        self.alerts_df = self._load_alerts()
        self.metrics = self._calculate_metrics()
    
    def _load_alerts(self) -> pd.DataFrame:
        """Load alert data"""
        # Try to load from file
        alerts_file = self.data_dir / "alerts.json"
        if alerts_file.exists():
            try:
                with open(alerts_file, 'r') as f:
                    alerts = json.load(f)
                return pd.DataFrame(alerts)
            except Exception as e:
                logger.warning(f"Failed to load alerts: {e}")
        
        # Generate mock data
        return self._generate_mock_data()
    
    def _generate_mock_data(self) -> pd.DataFrame:
        """Generate mock alert data for demo"""
        import random
        
        # MITRE tactics
        tactics = [
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "exfiltration", "command_and_control", "impact"
        ]
        
        # Techniques per tactic
        techniques = {
            "initial_access": ["T1190", "T1133", "T1566"],
            "execution": ["T1059", "T1059.001", "T1047"],
            "persistence": ["T1053", "T1543", "T1547"],
            "privilege_escalation": ["T1548", "T1068", "T1134"],
            "defense_evasion": ["T1070", "T1027", "T1036"],
            "credential_access": ["T1110", "T1003", "T1558"],
            "discovery": ["T1046", "T1087", "T1018"],
            "lateral_movement": ["T1021", "T1570", "T1550"],
            "collection": ["T1005", "T1114", "T1056"],
            "exfiltration": ["T1048", "T1041", "T1567"],
            "command_and_control": ["T1071", "T1105", "T1572"],
            "impact": ["T1486", "T1499"]
        }
        
        # Severity levels
        severities = ["critical", "high", "medium", "low", "info"]
        
        # Generate alerts
        alerts = []
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(100):
            tactic = random.choice(tactics)
            technique = random.choice(techniques[tactic])
            severity = random.choices(
                severities,
                weights=[10, 30, 40, 15, 5]
            )[0]
            
            alert_time = base_time + timedelta(
                hours=random.randint(0, 168),
                minutes=random.randint(0, 59)
            )
            
            alerts.append({
                "alert_id": f"ALERT-{i+1:04d}",
                "timestamp": alert_time.isoformat(),
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "destination_ip": f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}",
                "user": f"user_{random.randint(1, 50)}",
                "process": f"process_{random.randint(1, 100)}.exe",
                "severity": severity,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "ml_score": random.uniform(0.1, 0.95),
                "status": random.choice(["new", "investigating", "resolved", "false_positive"]),
                "rule_name": f"Rule-{random.randint(1, 51)}"
            })
        
        return pd.DataFrame(alerts)
    
    def _calculate_metrics(self) -> Dict[str, Any]:
        """Calculate dashboard metrics"""
        df = self.alerts_df
        
        return {
            "total_alerts": len(df),
            "critical_alerts": len(df[df['severity'] == 'critical']),
            "high_alerts": len(df[df['severity'] == 'high']),
            "medium_alerts": len(df[df['severity'] == 'medium']),
            "low_alerts": len(df[df['severity'] == 'low']),
            "info_alerts": len(df[df['severity'] == 'info']),
            "mean_time_to_detect": "15 minutes",
            "false_positive_rate": "15%",
            "true_positive_rate": "95%",
            "alerts_today": len(df[df['timestamp'] >= datetime.now().isoformat()[:10]]),
            "alerts_by_tactic": df['mitre_tactic'].value_counts().to_dict(),
            "alerts_by_status": df['status'].value_counts().to_dict()
        }
    
    def render_header(self):
        """Render dashboard header"""
        st.markdown('<div class="main-header">🛡️ SOC Dashboard - AI-Powered Threat Detection</div>', unsafe_allow_html=True)
        st.markdown("---")
    
    def render_metrics(self):
        """Render key metrics"""
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                label="Total Alerts",
                value=self.metrics['total_alerts'],
                delta="+12 today"
            )
        
        with col2:
            st.metric(
                label="Critical",
                value=self.metrics['critical_alerts'],
                delta="-2",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                label="High",
                value=self.metrics['high_alerts'],
                delta="+5"
            )
        
        with col4:
            st.metric(
                label="MTTD",
                value=self.metrics['mean_time_to_detect'],
                delta="-25 min",
                delta_color="inverse"
            )
        
        with col5:
            st.metric(
                label="FP Rate",
                value=self.metrics['false_positive_rate'],
                delta="-5%",
                delta_color="inverse"
            )
    
    def render_alert_trend(self):
        """Render alert trend chart"""
        st.subheader("📈 Alert Trend (Last 7 Days)")
        
        df = self.alerts_df.copy()
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        
        daily_counts = df.groupby(['date', 'severity']).size().reset_index(name='count')
        
        fig = px.bar(
            daily_counts,
            x='date',
            y='count',
            color='severity',
            title="Daily Alert Volume by Severity",
            color_discrete_map={
                'critical': '#ff4b4b',
                'high': '#ff8c00',
                'medium': '#ffd700',
                'low': '#90ee90',
                'info': '#87ceeb'
            }
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_mitre_heatmap(self):
        """Render MITRE ATT&CK heatmap"""
        st.subheader("🎯 MITRE ATT&CK Coverage")
        
        # Create heatmap data
        tactics = [
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "exfiltration", "command_and_control", "impact"
        ]
        
        coverage = {
            "ta": tactics,
            "detection_rate": [95, 88, 82, 78, 85, 90, 75, 80, 70, 88, 85, 92]
        }
        
        df_coverage = pd.DataFrame(coverage)
        
        fig = px.bar(
            df_coverage,
            x='ta',
            y='detection_rate',
            title="Detection Coverage by MITRE Tactic",
            color='detection_rate',
            color_continuous_scale='RdYlGn',
            range_color=[0, 100]
        )
        
        fig.update_layout(xaxis_title="MITRE Tactic", yaxis_title="Detection Rate (%)")
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_alert_feed(self):
        """Render real-time alert feed"""
        st.subheader("🔔 Recent Alerts")
        
        df = self.alerts_df.sort_values('timestamp', ascending=False).head(20)
        
        for _, alert in df.iterrows():
            severity_class = f"severity-{alert['severity']}"
            
            with st.expander(f"**{alert['alert_id']}** - {alert['severity'].upper()} - {alert['mitre_technique']}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Time:** {alert['timestamp'][:19]}")
                    st.write(f"**Source:** {alert['source_ip']}")
                    st.write(f"**Destination:** {alert['destination_ip']}")
                
                with col2:
                    st.write(f"**User:** {alert['user']}")
                    st.write(f"**Process:** {alert['process']}")
                    st.write(f"**Rule:** {alert['rule_name']}")
                
                with col3:
                    st.write(f"**MITRE Tactic:** {alert['mitre_tactic']}")
                    st.write(f"**MITRE Technique:** {alert['mitre_technique']}")
                    st.write(f"**ML Score:** {alert['ml_score']:.2f}")
                
                st.write(f"**Status:** {alert['status']}")
    
    def render_severity_distribution(self):
        """Render severity distribution"""
        st.subheader("📊 Alert Severity Distribution")
        
        severity_counts = self.alerts_df['severity'].value_counts()
        
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="Alert Severity Distribution",
            color=severity_counts.index,
            color_discrete_map={
                'critical': '#ff4b4b',
                'high': '#ff8c00',
                'medium': '#ffd700',
                'low': '#90ee90',
                'info': '#87ceeb'
            }
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_detection_rules(self):
        """Render detection rules overview"""
        st.subheader("📋 Detection Rules")
        
        # Sigma rules summary
        sigma_rules = {
            "TA0043 Reconnaissance": 3,
            "TA0001 Initial Access": 5,
            "TA0002 Execution": 5,
            "TA0003 Persistence": 6,
            "TA0004 Privilege Escalation": 4,
            "TA0005 Defense Evasion": 5,
            "TA0006 Credential Access": 4,
            "TA0007 Discovery": 4,
            "TA0008 Lateral Movement": 4,
            "TA0009 Collection": 3,
            "TA0010 Exfiltration": 3,
            "TA0011 Command & Control": 3,
            "TA0040 Impact": 2
        }
        
        # YARA rules summary
        yara_rules = {
            "Ransomware": 5,
            "Trojans": 5,
            "Backdoors": 4,
            "Webshells": 3,
            "Cryptominers": 3
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Sigma Rules (51 total)**")
            fig_sigma = px.bar(
                x=list(sigma_rules.values()),
                y=list(sigma_rules.keys()),
                orientation='h',
                title="Sigma Rules by MITRE Tactic"
            )
            st.plotly_chart(fig_sigma, use_container_width=True)
        
        with col2:
            st.write("**YARA Rules (20 total)**")
            fig_yara = px.bar(
                x=list(yara_rules.values()),
                y=list(yara_rules.keys()),
                orientation='h',
                title="YARA Rules by Category"
            )
            st.plotly_chart(fig_yara, use_container_width=True)
    
    def render_sidebar(self):
        """Render sidebar"""
        st.sidebar.title("🛡️ SOC Dashboard")
        st.sidebar.markdown("---")
        
        # Filters
        st.sidebar.subheader("Filters")
        
        severity_filter = st.sidebar.multiselect(
            "Severity",
            options=["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium", "low", "info"]
        )
        
        tactic_filter = st.sidebar.multiselect(
            "MITRE Tactic",
            options=self.alerts_df['mitre_tactic'].unique().tolist(),
            default=self.alerts_df['mitre_tactic'].unique().tolist()
        )
        
        status_filter = st.sidebar.multiselect(
            "Status",
            options=["new", "investigating", "resolved", "false_positive"],
            default=["new", "investigating", "resolved", "false_positive"]
        )
        
        # Apply filters
        filtered_df = self.alerts_df[
            (self.alerts_df['severity'].isin(severity_filter)) &
            (self.alerts_df['mitre_tactic'].isin(tactic_filter)) &
            (self.alerts_df['status'].isin(status_filter))
        ]
        
        st.sidebar.write(f"**Showing {len(filtered_df)} of {len(self.alerts_df)} alerts**")
        
        # Quick stats
        st.sidebar.markdown("---")
        st.sidebar.subheader("Quick Stats")
        st.sidebar.write(f"Critical: {len(filtered_df[filtered_df['severity'] == 'critical'])}")
        st.sidebar.write(f"High: {len(filtered_df[filtered_df['severity'] == 'high'])}")
        st.sidebar.write(f"Medium: {len(filtered_df[filtered_df['severity'] == 'medium'])}")
        st.sidebar.write(f"Low: {len(filtered_df[filtered_df['severity'] == 'low'])}")
        
        return filtered_df
    
    def render(self):
        """Render complete dashboard"""
        self.render_header()
        
        # Sidebar with filters
        filtered_df = self.render_sidebar()
        
        # Main content
        self.render_metrics()
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            self.render_alert_trend()
        
        with col2:
            self.render_severity_distribution()
        
        self.render_mitre_heatmap()
        
        self.render_alert_feed()
        
        self.render_detection_rules()


def main():
    """Main function"""
    dashboard = SOCDashboard()
    dashboard.render()


if __name__ == "__main__":
    main()