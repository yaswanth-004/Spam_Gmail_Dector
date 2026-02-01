import streamlit as st
import os
from main import (
    get_gmail_service,
    fetch_and_hash_emails,
    ai_model,
    ai_vectorizer,
    VIRUSTOTAL_API_KEY
)

# Page configuration
st.set_page_config(
    page_title="Gmail Spam Scanner",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .status-box {
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .status-success {
        background-color: #d4edda;
        border-left: 5px solid #28a745;
    }
    .status-warning {
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
    }
    .status-danger {
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
    }
    .email-card {
        background-color: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border: 1px solid #dee2e6;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'service' not in st.session_state:
    st.session_state.service = None
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []

# Header
st.markdown('<div class="main-header">📧 Gmail Spam Scanner</div>', unsafe_allow_html=True)
st.markdown("### AI-Powered Email Security with VirusTotal Integration")

# Sidebar - Configuration & Status
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # System Status
    st.subheader("System Status")
    
    # AI Model Status
    if ai_model and ai_vectorizer:
        st.markdown('<div class="status-box status-success">✅ AI Spam Model Loaded</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-box status-danger">❌ AI Model Not Loaded</div>', unsafe_allow_html=True)
    
    # VirusTotal Status
    if VIRUSTOTAL_API_KEY:
        st.markdown('<div class="status-box status-success">✅ VirusTotal API Connected</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-box status-warning">⚠️ VirusTotal Not Configured</div>', unsafe_allow_html=True)
        st.info("Set VIRUSTOTAL_API_KEY in .env file to enable URL/file scanning")
    
    # Gmail Authentication Status
    if st.session_state.authenticated:
        st.markdown('<div class="status-box status-success">✅ Gmail Connected</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-box status-warning">⚠️ Gmail Not Connected</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Quick Stats
    if st.session_state.scan_results:
        st.subheader("📊 Scan Statistics")
        total_emails = len(st.session_state.scan_results)
        spam_count = sum(1 for email in st.session_state.scan_results if email['ai_verdict'] == 'SPAM')
        ham_count = sum(1 for email in st.session_state.scan_results if email['ai_verdict'] == 'HAM')
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Scanned", total_emails)
        with col2:
            st.metric("Spam Detected", spam_count, delta=f"{(spam_count/total_emails*100):.1f}%")
        
        st.metric("Legitimate", ham_count, delta=f"{(ham_count/total_emails*100):.1f}%")

# Main Content
tab1, tab2, tab3 = st.tabs(["🔍 Scan Emails", "📊 Results", "ℹ️ About"])

with tab1:
    st.header("Email Scanner")
    
    # Authentication Section
    if not st.session_state.authenticated:
        st.info("👉 Click below to authenticate with your Gmail account")
        
        if st.button("🔐 Connect to Gmail", type="primary", use_container_width=True):
            with st.spinner("Authenticating with Gmail..."):
                try:
                    service = get_gmail_service()
                    if service:
                        st.session_state.service = service
                        st.session_state.authenticated = True
                        st.success("✅ Successfully connected to Gmail!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to connect to Gmail. Check credentials.json file.")
                except Exception as e:
                    st.error(f"❌ Authentication error: {str(e)}")
    
    else:
        st.success("✅ Gmail account connected")
        
        # Scan Configuration
        st.subheader("Scan Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            folder = st.selectbox(
                "Select Folder",
                ["INBOX", "SPAM", "SENT", "TRASH", "STARRED", "DRAFT"],
                index=0
            )
            
            max_emails = st.slider(
                "Number of Emails to Scan",
                min_value=1,
                max_value=100,
                value=10,
                help="Maximum 100 emails per scan"
            )
        
        with col2:
            date_filter = st.checkbox("Apply Date Filter")
            
            if date_filter:
                start_date = st.date_input("Start Date")
                end_date = st.date_input("End Date")
            
            enable_vt = st.checkbox(
                "Enable VirusTotal Scanning",
                value=True if VIRUSTOTAL_API_KEY else False,
                disabled=not VIRUSTOTAL_API_KEY,
                help="Scan URLs and attachments with VirusTotal (requires API key)"
            )
        
        # Search Filter
        with st.expander("🔎 Advanced Search Filters"):
            filter_type = st.radio(
                "Filter by",
                ["None", "Domain", "Email Address"]
            )
            
            if filter_type != "None":
                search_term = st.text_input(
                    f"Enter {filter_type}",
                    placeholder=f"e.g., {'example.com' if filter_type == 'Domain' else 'user@example.com'}"
                )
        
        st.divider()
        
        # Scan Button
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            # Build query
            query = f"in:{folder}"
            
            if date_filter:
                query += f" after:{start_date.strftime('%Y-%m-%d')}"
                query += f" before:{end_date.strftime('%Y-%m-%d')}"
            
            if filter_type == "Domain" and 'search_term' in locals() and search_term:
                query += f" from:@{search_term}"
            elif filter_type == "Email Address" and 'search_term' in locals() and search_term:
                query += f" from:\"{search_term}\""
            
            st.info(f"🔍 Query: `{query}`")
            
            # Perform scan
            with st.spinner(f"Scanning {max_emails} emails from {folder}..."):
                try:
                    results = fetch_and_hash_emails(
                        st.session_state.service,
                        query,
                        max_emails,
                        folder,
                        enable_vt_scan=enable_vt
                    )
                    
                    st.session_state.scan_results = results
                    
                    if results:
                        st.success(f"✅ Successfully scanned {len(results)} emails!")
                        st.balloons()
                    else:
                        st.warning("No emails found matching your criteria.")
                        
                except Exception as e:
                    st.error(f"❌ Scan error: {str(e)}")

with tab2:
    st.header("Scan Results")
    
    if not st.session_state.scan_results:
        st.info("👈 No scan results yet. Start a scan from the 'Scan Emails' tab.")
    else:
        # Filter options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            verdict_filter = st.selectbox(
                "Filter by Verdict",
                ["All", "SPAM", "HAM", "NO_CONTENT"]
            )
        
        with col2:
            sort_by = st.selectbox(
                "Sort by",
                ["Date (Newest)", "Date (Oldest)", "Spam First", "Safe First"]
            )
        
        with col3:
            st.download_button(
                "📥 Download Results (JSON)",
                data=str(st.session_state.scan_results),
                file_name="scan_results.json",
                mime="application/json"
            )
        
        st.divider()
        
        # Display results
        filtered_results = st.session_state.scan_results
        
        if verdict_filter != "All":
            filtered_results = [r for r in filtered_results if r['ai_verdict'] == verdict_filter]
        
        for idx, email in enumerate(filtered_results):
            # Verdict icon
            if email['ai_verdict'] == "SPAM":
                verdict_icon = "🔴"
                verdict_class = "status-danger"
            elif email['ai_verdict'] == "HAM":
                verdict_icon = "🟢"
                verdict_class = "status-success"
            else:
                verdict_icon = "⚪"
                verdict_class = "status-warning"
            
            with st.expander(f"{verdict_icon} **{email['subject'] or '(No Subject)'}** - {email['from'][:50]}"):
                st.markdown(f'<div class="email-card">', unsafe_allow_html=True)
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**From:** {email['from']}")
                    st.markdown(f"**Date:** {email['date']}")
                    st.markdown(f"**Subject:** {email['subject'] or '(No Subject)'}")
                
                with col2:
                    st.markdown(f'<div class="status-box {verdict_class}">', unsafe_allow_html=True)
                    st.markdown(f"**AI Verdict:** {verdict_icon} {email['ai_verdict']}")
                    st.markdown('</div>', unsafe_allow_html=True)
                
                st.markdown("---")
                st.markdown(f"**Preview:** {email['snippet'][:200]}...")
                st.markdown(f"**Hash:** `{email['hash'][:32]}...`")
                
                # URLs
                if email.get('urls'):
                    st.markdown("**🔗 URLs Found:**")
                    for url_data in email['urls']:
                        st.text(url_data['url'][:80])
                        if 'report' in url_data:
                            st.code(url_data['report'], language='text')
                
                # Attachments
                if email.get('attachments'):
                    st.markdown("**📁 Attachments:**")
                    for att_data in email['attachments']:
                        st.text(att_data['filename'])
                        if 'report' in att_data:
                            st.code(att_data['report'], language='text')
                
                st.markdown('</div>', unsafe_allow_html=True)

with tab3:
    st.header("About Gmail Spam Scanner")
    
    st.markdown("""
    ### 🎯 Features
    
    - **AI-Powered Spam Detection**: Machine learning model trained to identify spam emails
    - **VirusTotal Integration**: Scan URLs and file attachments for malware
    - **Multiple Folder Support**: Scan INBOX, SPAM, SENT, and other folders
    - **Advanced Filtering**: Filter by date range, domain, or email address
    - **Real-time Results**: See scan results instantly in an interactive dashboard
    
    ### 🔒 Security & Privacy
    
    - **Secure Authentication**: OAuth 2.0 for Gmail API access
    - **API Key Protection**: VirusTotal API key stored in `.env` file (never in code)
    - **Rate Limiting**: Automatic rate limiting to prevent API abuse
    - **Local Processing**: All AI predictions run locally on your machine
    
    ### 🚀 How to Use
    
    1. **Setup**:
        - Place `credentials.json` from Google Cloud Console in the project folder
        - Create `.env` file with `VIRUSTOTAL_API_KEY=your_key_here`
        - Install requirements: `pip install -r requirements.txt`
    
    2. **Run**:
        - Start Streamlit: `streamlit run streamlit_app.py`
        - Connect to Gmail using the authentication button
        - Configure your scan settings
        - Click "Start Scan" and view results!
    
    3. **Results**:
        - View detailed analysis of each email
        - Filter and sort results
        - Download scan data for further analysis
    
    ### 📊 AI Model Details
    
    - **Algorithm**: Machine Learning Classifier
    - **Training Data**: Large email spam dataset
    - **Features**: Text vectorization with TF-IDF
    - **Accuracy**: Trained on real-world spam/ham examples
    
    ### ⚙️ Technical Stack
    
    - **Frontend**: Streamlit
    - **Backend**: Python 3.x
    - **APIs**: Gmail API, VirusTotal API
    - **ML**: scikit-learn, joblib
    - **Security**: python-dotenv for environment variables
    
    ### 📝 License & Credits
    
    This project is designed for educational and personal use.
    Always comply with Gmail's Terms of Service and VirusTotal's API usage guidelines.
    
    ---
    
    **Need Help?**
    - Check that `credentials.json` is in the project directory
    - Ensure `.env` file has your VirusTotal API key
    - Verify `spam_model.pkl` and `vectorizer.pkl` are present
    """)
    
    st.info("💡 **Tip**: For best results, scan your SPAM folder to test the AI detection capabilities!")

# Footer
st.divider()
st.markdown(
    '<div style="text-align: center; color: #6c757d; padding: 1rem;">'
    '📧 Gmail Spam Scanner v1.0 | Built with ❤️ using Streamlit'
    '</div>',
    unsafe_allow_html=True
)