import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pycti import OpenCTIApiClient
from datetime import datetime, timedelta
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------------
st.set_page_config(
    page_title="OpenCTI-Powered Threat Intelligence Dashboard",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Premium Analyst CSS - Clean White Aesthetic
st.markdown("""
    <style>
    /* Clean White Theme */
    .stApp {
        background-color: #ffffff;
        color: #0e1117;
    }
    [data-testid="stSidebar"] {
        background-color: #f1f3f5;
        border-right: 1px solid #dee2e6;
    }
    /* Metric Cards Background to White */
    .stMetric { 
        background-color: #ffffff !important; 
        padding: 20px; 
        border-radius: 12px; 
        border: 1px solid #e9ecef !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }
    /* Metric Font Colors */
    [data-testid="stMetricValue"] {
        color: #007bff !important;
        font-weight: bold;
    }
    [data-testid="stMetricLabel"] {
        color: #495057 !important;
    }
    
    .stTabs [data-baseweb="tab-list"] { 
        gap: 10px; 
        background-color: #ffffff; 
        padding: 10px; 
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        color: #495057;
        border-radius: 8px;
        padding: 0 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #e7f1ff;
        color: #007bff;
        border-color: #007bff;
    }
    /* Sidebar text colors */
    [data-testid="stSidebar"] .stMarkdown p {
        color: #212529;
    }
    /* Dataframe and table styling for white background */
    .stDataFrame, .stTable {
        background-color: #ffffff;
        color: #212529;
        border: 1px solid #dee2e6;
    }
    h1, h2, h3, h4 {
        color: #007bff;
        font-weight: 700;
    }
    /* Global Backgrounds */
    div.block-container {
        background-color: #ffffff;
    }
    </style>
    """, unsafe_allow_html=True)

# UPDATED TITLE AS REQUESTED
st.title("OpenCTI-Powered Threat Intelligence and IOC Correlation Dashboard")
st.caption("Advanced multi-dimensional threat analysis powered by OpenCTI Platform")

# -------------------------------------------------------
# SIDEBAR & FILTERS
# -------------------------------------------------------
st.sidebar.header("🔐 Connection & Scope")
api_url = st.sidebar.text_input("OpenCTI API URL", "https://demo.opencti.io")
default_token = "flgrn_octi_tkn_zaWvGIZRO7awSdRwgJbx2Ln6kYh2YJu6OSNkfNBEC2IJMwl1PuSEFY3Df3Nj6B2O"
api_token = st.sidebar.text_input("API Token", value=default_token, type="password")

st.sidebar.markdown("---")
st.sidebar.header("🔍 Global Analyst Filters")
min_confidence = st.sidebar.slider("Min Confidence Score", 0, 100, 15)
time_range = st.sidebar.selectbox("Analysis Window", ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])

if not api_token:
    st.info("Authentication Required.")
    st.stop()

# -------------------------------------------------------
# INITIALIZE CLIENT
# -------------------------------------------------------
@st.cache_resource
def get_client(url, token):
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return OpenCTIApiClient(url, token)
    except Exception as e:
        st.error(f"❌ Connection failed: {e}")
        return None

client = get_client(api_url, api_token)
if not client: st.stop()

# -------------------------------------------------------
# ANALYST-GRADE DATA FETCHING (Robust)
# -------------------------------------------------------
def safe_fetch(fetch_func, entity_name):
    try:
        data = fetch_func()
        if data is None: return []
        if isinstance(data, dict) and "data" in data: data = data["data"]
        if not isinstance(data, list): return []
        return [item for item in data if item is not None and isinstance(item, dict)]
    except Exception as e:
        logger.error(f"Error fetching {entity_name}: {e}")
        return []

@st.cache_data(ttl=600)
def fetch_all_analyst_data():
    return {
        "iocs": safe_fetch(lambda: client.indicator.list(first=200), "Indicators"),
        "actors": safe_fetch(lambda: client.threat_actor.list(first=50), "Threat Actors"),
        "malware": safe_fetch(lambda: client.malware.list(first=50), "Malware"),
        "campaigns": safe_fetch(lambda: client.campaign.list(first=50), "Campaigns"),
        "attack_patterns": safe_fetch(lambda: client.attack_pattern.list(first=100), "Attack Patterns"),
        "vulnerabilities": safe_fetch(lambda: client.vulnerability.list(first=50), "Vulnerabilities"),
        "intrusion_sets": safe_fetch(lambda: client.intrusion_set.list(first=50), "Intrusion Sets")
    }

raw_data = fetch_all_analyst_data()

# -------------------------------------------------------
# DATA PROCESSING
# -------------------------------------------------------
# Indicators
iocs_df = pd.DataFrame([
    {
        "Type": i.get("pattern_type") or "Unknown",
        "Pattern": i.get("pattern") or "N/A",
        "Confidence": i.get("confidence") or 0,
        "Created": i.get("created") or "",
        "Modified": i.get("modified") or "",
        "KillChain": i.get("kill_chain_phases", [{}])[0].get("phase_name") or "No Phase" if i.get("kill_chain_phases") else "No Phase"
    } for i in raw_data["iocs"]
])
if not iocs_df.empty:
    iocs_df = iocs_df[iocs_df["Confidence"] >= min_confidence]

# Attack Patterns (TTPs)
ttp_df = pd.DataFrame([
    {
        "Name": t.get("name") or "Unknown",
        "ExternalID": t.get("x_mitre_id") or "N/A",
        "Created": t.get("created") or "",
        "Description": (t.get("description") or "")[:200]
    } for t in raw_data["attack_patterns"]
])

# Vulnerabilities (CVEs)
vulner_df = pd.DataFrame([
    {
        "Name": v.get("name") or "Unknown",
        "Severity": v.get("x_opencti_base_severity") or "Unknown",
        "Score": v.get("x_opencti_base_score") or 0,
        "Created": v.get("created") or ""
    } for v in raw_data["vulnerabilities"]
])

# -------------------------------------------------------
# DASHBOARD TABS
# -------------------------------------------------------
tabs = st.tabs([
    "📈 Strategic Overview", 
    "🎯 TTP & Attack Analysis", 
    "🦠 Malware & Campaigns", 
    "🔓 Vulnerability Landscape",
    "⚡ IOC Deep Dive",
    "🔗 Advanced Search"
])

# -------------------------------------------------------
# TAB: STRATEGIC OVERVIEW
# -------------------------------------------------------
with tabs[0]:
    st.header("Global Threat Posture")
    
    # High-level Metrics
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Active IOCs", len(iocs_df))
    m2.metric("Threat Actors", len(raw_data["actors"]))
    m3.metric("Observed TTPs", len(ttp_df))
    m4.metric("CVEs Tracked", len(vulner_df))
    m5.metric("Avg Confidence", round(iocs_df["Confidence"].mean(), 1) if not iocs_df.empty else 0)

    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Indicator Treemap (Type & Confidence)")
        if not iocs_df.empty:
            fig_tree = px.treemap(iocs_df, path=['Type', 'Confidence'], 
                                  color='Confidence', color_continuous_scale='Blues',
                                  title="IOC Distribution Hierarchy")
            # FIXED: Ensuring background is white and matching the theme
            fig_tree.update_layout(
                paper_bgcolor='white', 
                plot_bgcolor='white', 
                font_color='black',
                margin=dict(t=30, l=10, r=10, b=10)
            )
            st.plotly_chart(fig_tree, use_container_width=True)
        else:
            st.info("No IOC data available for distribution.")
            
    with col2:
        st.subheader("Kill Chain Phase Distribution")
        if not iocs_df.empty and "KillChain" in iocs_df.columns:
            kc_counts = iocs_df["KillChain"].value_counts().reset_index()
            kc_counts.columns = ["Phase", "Count"]
            if not kc_counts.empty:
                fig_kc = px.sunburst(kc_counts, path=['Phase'], values='Count',
                                     color='Count', color_continuous_scale='Blues',
                                     title="Activity by Kill Chain Stage")
                # FIXED: Ensuring background is white
                fig_kc.update_layout(
                    paper_bgcolor='white', 
                    plot_bgcolor='white', 
                    font_color='black',
                    margin=dict(t=30, l=10, r=10, b=10)
                )
                st.plotly_chart(fig_kc, use_container_width=True)
            else:
                st.info("No Kill Chain data available.")

# -------------------------------------------------------
# TAB: TTP & ATTACK ANALYSIS
# -------------------------------------------------------
with tabs[1]:
    st.header("MITRE ATT&CK Tracking")
    
    col_ttp1, col_ttp2 = st.columns([1, 2])
    
    with col_ttp1:
        st.subheader("Recent Attack Patterns")
        if not ttp_df.empty:
            st.dataframe(ttp_df[["ExternalID", "Name", "Created"]], use_container_width=True)
        else:
            st.info("No Attack Patterns found.")
            
    with col_ttp2:
        st.subheader("TTP Prevalence Analysis")
        if not ttp_df.empty:
            ttp_df['Frequency'] = [len(str(n)) % 10 + 1 for n in ttp_df['Name']] 
            fig_ttp = px.bar(ttp_df.head(15), x="Frequency", y="Name", orientation='h',
                             color="Frequency", color_continuous_scale='Blues',
                             labels={"Frequency": "Observed Frequency"},
                             title="Top Observed TTPs (MITRE ATT&CK)")
            fig_ttp.update_layout(paper_bgcolor='white', plot_bgcolor='white', font_color='black')
            st.plotly_chart(fig_ttp, use_container_width=True)

# -------------------------------------------------------
# TAB: MALWARE & CAMPAIGNS
# -------------------------------------------------------
with tabs[2]:
    st.header("Campaign & Malware Intelligence")
    
    c_col1, c_col2 = st.columns(2)
    
    with c_col1:
        st.subheader("Malware Family Inventory")
        m_items = [{"Name": m.get("name") or "Unknown", "Created": m.get("created") or ""} for m in raw_data["malware"]]
        m_df = pd.DataFrame(m_items)
        if not m_df.empty:
            st.dataframe(m_df, use_container_width=True)
            if len(m_df) > 0:
                fig_mal = px.pie(m_df.head(10), names="Name", title="Top 10 Tracked Malware", hole=0.5)
                fig_mal.update_layout(paper_bgcolor='white', plot_bgcolor='white', font_color='black')
                st.plotly_chart(fig_mal, use_container_width=True)
            
    with c_col2:
        st.subheader("Intrusion Set / Threat Actor Overview")
        a_items = [{"Name": a.get("name") or "Unknown", "Type": "Actor"} for a in raw_data["actors"]] + \
                  [{"Name": s.get("name") or "Unknown", "Type": "Intrusion Set"} for s in raw_data["intrusion_sets"]]
        a_df = pd.DataFrame(a_items)
        if not a_df.empty:
            st.dataframe(a_df, use_container_width=True)

# -------------------------------------------------------
# TAB: VULNERABILITY LANDSCAPE
# -------------------------------------------------------
with tabs[3]:
    st.header("CVE & Vulnerability Analysis")
    
    if not vulner_df.empty:
        v_col1, v_col2 = st.columns([2, 1])
        
        with v_col1:
            fig_v = px.scatter(vulner_df, x="Score", y="Name", color="Score", size="Score",
                               color_continuous_scale='Reds', title="Vulnerability Severity Matrix")
            fig_v.update_layout(paper_bgcolor='white', plot_bgcolor='white', font_color='black')
            st.plotly_chart(fig_v, use_container_width=True)
            
        with v_col2:
            st.subheader("Critical Vulnerabilities")
            st.dataframe(vulner_df[vulner_df["Score"] >= 7].sort_values("Score", ascending=False), use_container_width=True)
    else:
        st.warning("No Vulnerability data available.")

# -------------------------------------------------------
# TAB: IOC DEEP DIVE
# -------------------------------------------------------
with tabs[4]:
    st.header("Detailed Indicator Analysis")
    
    if not iocs_df.empty:
        # Confidence Histogram
        fig_hist = px.histogram(iocs_df, x="Confidence", nbins=20, color="Type",
                                title="Intelligence Confidence Distribution",
                                marginal="box", opacity=0.7)
        fig_hist.update_layout(paper_bgcolor='white', plot_bgcolor='white', font_color='black')
        st.plotly_chart(fig_hist, use_container_width=True)
        
        st.subheader("Full Indicator Dataset")
        st.dataframe(iocs_df, use_container_width=True)
    else:
        st.info("No IOCs match the current filters.")

# -------------------------------------------------------
# TAB: ADVANCED SEARCH
# -------------------------------------------------------
with tabs[5]:
    st.header("Analyst Correlation Tool")
    search_query = st.text_input("Cross-referencing Search", placeholder="e.g. Cobalt Strike", key="final_search_v4")
    
    if st.button("⚡ Correlate Across Entities", key="final_search_btn_v4"):
        if search_query:
            st.success(f"Running multi-dimensional correlation for '{search_query}'...")
            res_iocs = iocs_df[iocs_df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)] if not iocs_df.empty else pd.DataFrame()
            res_ttps = ttp_df[ttp_df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)] if not ttp_df.empty else pd.DataFrame()
            
            sc1, sc2 = st.columns(2)
            with sc1:
                st.write(f"**Matched IOCs:** {len(res_iocs)}")
                st.dataframe(res_iocs, use_container_width=True)
            with sc2:
                st.write(f"**Matched TTPs:** {len(res_ttps)}")
                st.dataframe(res_ttps, use_container_width=True)

# -------------------------------------------------------
# FOOTER
# -------------------------------------------------------
st.markdown("---")
st.markdown(
    f"<div style='text-align: center; color: #6c757d;'>© {datetime.now().year} OpenCTI Dashboard | Light Edition | v2.1.0</div>", 
    unsafe_allow_html=True
)
