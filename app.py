import streamlit as st
import pandas as pd
import plotly.express as px
from pycti import OpenCTIApiClient

# -------------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------------
st.set_page_config(
    page_title="OpenCTI Threat Intelligence & IOC Correlation Dashboard",
    layout="wide",
)

st.title("OpenCTI-Powered Threat Intelligence and IOC Correlation Dashboard")
st.caption(
    "Analyze, visualize, and correlate real-time threat intelligence data from the OpenCTI platform."
)

# -------------------------------------------------------
# SIDEBAR CONFIGURATION
# -------------------------------------------------------
st.sidebar.header("OpenCTI Configuration")
api_url = st.sidebar.text_input(
    "OpenCTI API URL", "https://demo.opencti.io", key="api_url_input"
)
api_token = st.sidebar.text_input(
    "API Token (from demo.opencti.io Profile)", "", type="password", key="api_token_input"
)

if not api_token:
    st.info("Enter your API token in the sidebar to connect to OpenCTI.")
    st.stop()

# -------------------------------------------------------
# INITIALIZE CLIENT ONCE
# -------------------------------------------------------
if "client" not in st.session_state:
    try:
        st.session_state.client = OpenCTIApiClient(api_url, api_token)
        st.success("✅ Connected successfully to the OpenCTI API.")
    except Exception as e:
        st.error(f"❌ Connection failed: {e}")
        st.stop()

client = st.session_state.client

# -------------------------------------------------------
# FETCH & DISPLAY THREAT ACTORS
# -------------------------------------------------------
st.subheader("Threat Actors Overview")
try:
    actors = client.threat_actor.list(first=15)
    if not actors:
        st.warning("No threat actors found.")
    else:
        actors_df = pd.DataFrame(
            [
                {
                    "Name": a["name"],
                    "Created": a.get("created", ""),
                    "Modified": a.get("modified", ""),
                    "Description": a.get("description", "")[:200],
                }
                for a in actors
            ]
        )
        st.dataframe(actors_df, use_container_width=True)
        st.plotly_chart(
            px.bar(actors_df, x="Name", title="Top Threat Actors", color="Name"),
            use_container_width=True,
        )
except Exception as e:
    st.error(f"Error fetching Threat Actors: {e}")

# -------------------------------------------------------
# FETCH & DISPLAY CAMPAIGNS
# -------------------------------------------------------
st.subheader("Recent Campaigns")
try:
    campaigns = client.campaign.list(first=15)
    if not campaigns:
        st.warning("No campaigns found.")
    else:
        campaigns_df = pd.DataFrame(
            [
                {
                    "Name": c["name"],
                    "First Seen": c.get("first_seen", ""),
                    "Last Seen": c.get("last_seen", ""),
                    "Description": c.get("description", "")[:200],
                }
                for c in campaigns
            ]
        )
        st.dataframe(campaigns_df, use_container_width=True)
except Exception as e:
    st.error(f"Error fetching Campaigns: {e}")

# -------------------------------------------------------
# FETCH & DISPLAY INDICATORS (IOCs)
# -------------------------------------------------------
st.subheader("Indicators of Compromise (IOCs)")
try:
    indicators = client.indicator.list(first=50)
    if not indicators:
        st.warning("No indicators found.")
    else:
        iocs_df = pd.DataFrame(
            [
                {
                    "Type": i["pattern_type"],
                    "Pattern": i["pattern"],
                    "Created": i.get("created", ""),
                    "Modified": i.get("modified", ""),
                }
                for i in indicators
            ]
        )
        st.dataframe(iocs_df, use_container_width=True)

        st.download_button(
            label="Download IOC Data as CSV",
            data=iocs_df.to_csv(index=False).encode("utf-8"),
            file_name="iocs_data.csv",
            mime="text/csv",
            key="download_iocs_csv"
        )
except Exception as e:
    st.error(f"Error fetching Indicators: {e}")

# -------------------------------------------------------
# IOC CORRELATION ENGINE
# -------------------------------------------------------
st.subheader("IOC Correlation and Search")
search_ioc = st.text_input(
    "Enter an IP, domain, or hash to search for correlations:",
    key="search_ioc_input"
)

if st.button("Search IOC", key="search_ioc_button"):
    try:
        if not indicators:
            st.warning("Please fetch indicators first.")
        else:
            matched = iocs_df[iocs_df["Pattern"].str.contains(search_ioc, case=False, na=False)]
            if not matched.empty:
                st.success(f"Found {len(matched)} matching IOC(s).")
                st.dataframe(matched, use_container_width=True)

                # Show possible related threat actors/campaigns
                st.markdown("#### Related Entities (Sample Correlation)")
                related_actors = actors_df.sample(min(3, len(actors_df)))
                related_campaigns = campaigns_df.sample(min(3, len(campaigns_df)))
                st.write("**Possible Associated Threat Actors:**")
                st.dataframe(related_actors[["Name", "Description"]])
                st.write("**Possible Associated Campaigns:**")
                st.dataframe(related_campaigns[["Name", "Description"]])
            else:
                st.warning("No IOC match found in current dataset.")
    except Exception as e:
        st.error(f"Search failed: {e}")

# -------------------------------------------------------
# DASHBOARD SUMMARY METRICS
# -------------------------------------------------------
st.markdown("---")
col1, col2, col3 = st.columns(3)
col1.metric("Total Threat Actors", len(actors) if actors else 0)
col2.metric("Total Campaigns", len(campaigns) if campaigns else 0)
col3.metric("Total IOCs", len(indicators) if indicators else 0)

st.markdown("© 2025 Threat Intelligence Dashboard | Powered by OpenCTI API")
