# OpenCTI-Powered Threat Intelligence and IOC Correlation Dashboard 🕵️

An enterprise-grade security analytics platform designed to transform raw threat intelligence into actionable, visual insights. This dashboard integrates directly with the **OpenCTI ecosystem** to provide SOC analysts with a unified "single pane of glass" for tracking global threat actors, TTPs, and vulnerabilities.

---

## 📝 Project Description
This dashboard is a high-performance visualization suite built upon the **Open Cyber Threat Intelligence (OpenCTI)** framework. Utilizing the **pycti** Python SDK, it ingests structured STIX 2.1 data and presents it through a professional, high-fidelity web interface. 

### **Key Features:**
*   **Strategic Overview**: High-level posture assessment using Sunburst and Treemap visualizations.
*   **Tactical TTP Analysis**: Real-time mapping of adversary techniques to the **MITRE ATT&CK** framework.
*   **Vulnerability Matrix**: Risk-based prioritization of CVEs using real-world exploitation intelligence.
*   **Correlation Engine**: Advanced multi-dimensional search to uncover hidden links between Actors, Malware, and IOCs.

---

## ⚙️ Project Requirements

### **System Specifications**
*   **OS**: Windows 10/11, macOS, or Linux (64-bit)
*   **Memory**: 4 GB RAM (8 GB recommended)
*   **Python**: v3.10 or later

### **Software Dependencies**
*   **pycti**: Official OpenCTI Python Client.
*   **Streamlit**: Web application framework for the user interface.
*   **Plotly**: Interactive charting and data visualization library.
*   **Pandas**: High-speed data manipulation and transformation engine.

---

## 🗄️ Database Setup (OpenCTI)
This dashboard uses **OpenCTI** as its central intelligence database. You do not need to set up a local SQL/NoSQL database; instead, you connect to an OpenCTI instance via its API.

1.  **Host**: Use the official demo instance (`https://demo.opencti.io`) or your organization's local instance.
2.  **API Token**: 
    *   Log in to your OpenCTI platform.
    *   Navigate to **Profile > API Access**.
    *   Copy your unique alphanumeric API token.
3.  **Permissions**: Ensure your API account has "Analyst" or "Administrator" privileges to access all datasets.

---

## 🚀 How to Run the Project Locally

Follow these steps to launch the dashboard on your local machine:

### **1. Clone the Repository**
```bash
git clone https://github.com/OpenCTI-Platform/client-python.git
cd client-python
```

### **2. Set Up Virtual Environment**
```bash
# Create the environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate
```

### **3. Install Requirements**
```bash
pip install -r requirements.txt
pip install streamlit pandas plotly
```

### **4. Launch the Application**
```bash
streamlit run app.py
```

### **5. Access the Dashboard**
Open your browser and navigate to **`http://localhost:8501`**. Enter your OpenCTI URL and API Token in the sidebar to begin your intelligence session.

---

## 🛠️ Project Architecture
*   **Ingestion**: Secure GraphQL queries via `pycti`.
*   **Processing**: Automated data cleaning and entity correlation via `pandas`.
*   **Visualization**: Dynamic, high-fidelity rendering via `plotly`.
*   **Interface**: Professional "True White" analyst-first UI via `streamlit`.

---
*© 2026 OpenCTI Intelligence Dashboard | Enterprise Edition | v2.1.0*
