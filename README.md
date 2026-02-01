# 📧 Gmail Spam Scanner

AI-powered email security scanner with VirusTotal integration and modern web interface.

## ✨ Features

- 🤖 **AI-Powered Spam Detection**: Machine learning model for accurate spam identification
- 🔒 **VirusTotal Integration**: Scan URLs and file attachments for malware
- 🎨 **Modern Web UI**: Beautiful Streamlit interface for easy interaction
- 📊 **Detailed Analytics**: Comprehensive scan results with filtering and export
- 🔐 **Secure**: OAuth 2.0 authentication, environment-based API key management
- ⚡ **Rate Limiting**: Built-in protection against API rate limits

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Google Cloud Console account (for Gmail API)
- VirusTotal account (for malware scanning - optional)

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd gmail-spam-scanner
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Set up Gmail API**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project
   - Enable Gmail API
   - Create OAuth 2.0 credentials (Desktop app)
   - Download credentials and save as `credentials.json` in project root

4. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` and add your VirusTotal API key:
```
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

Get your free VirusTotal API key: https://www.virustotal.com/gui/join-us

5. **Add your AI model files**

Place these files in the project root:
- `spam_model.pkl` - Your trained spam detection model
- `vectorizer.pkl` - Your text vectorizer

## 🎯 Usage

### Command Line Interface

Run the CLI version:
```bash
python gmail_scanner.py
```

Follow the prompts to:
1. Authenticate with Gmail
2. Select folder to scan
3. Configure filters
4. View results

### Web Interface (Recommended)

Launch the Streamlit web app:
```bash
streamlit run streamlit_app.py
```

Then:
1. Open your browser to `http://localhost:8501`
2. Click "Connect to Gmail"
3. Configure scan settings
4. Click "Start Scan"
5. View and filter results in the dashboard

## 📁 Project Structure

```
gmail-spam-scanner/
├── gmail_scanner.py       # Core scanning logic
├── streamlit_app.py       # Web UI
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── spam_model.pkl        # AI model (not in repo)
├── vectorizer.pkl        # Vectorizer (not in repo)
└── credentials.json      # Gmail API credentials (not in repo)
```

## 🔒 Security Best Practices

### ✅ What IS Secure

- API keys stored in `.env` file (never committed to GitHub)
- OAuth 2.0 for Gmail authentication
- `.gitignore` prevents sensitive files from being pushed
- Rate limiting to prevent API abuse


### 🛡️ Recommended Setup

1. Always use `.env` for API keys
2. Never hardcode credentials in code
3. Use different API keys for development and production
4. Regularly rotate your API keys
5. Set up 2FA on your Google account

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with:

```bash
# Gmail API
GMAIL_CREDENTIALS_FILE=credentials.json

# VirusTotal API
VIRUSTOTAL_API_KEY=your_key_here

# Optional: Rate limiting (seconds between requests)
RATE_LIMIT_DELAY=15
```

### Rate Limiting

- **Free VirusTotal**: 4 requests/minute, 500 requests/day
- **Built-in delay**: 15 seconds between requests (configurable)
- **URL limit**: Scans first 3 URLs per email
- **Attachment limit**: Scans first 3 attachments per email

## 📊 AI Model Training

To train your own spam detection model:

1. Prepare dataset (CSV with 'text' and 'label' columns)
2. Use scikit-learn to train a classifier
3. Save model and vectorizer using joblib:

```python
import joblib
joblib.dump(model, 'spam_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
```

4. Place files in project root

## 🐛 Troubleshooting

### "credentials.json not found"
- Download OAuth credentials from Google Cloud Console
- Place in project root directory

### "VirusTotal API key not configured"
- Create `.env` file from `.env.example`
- Add your VirusTotal API key
- Restart the application

### "401 Unauthorized" from VirusTotal
- Verify API key is correct
- Check if email is verified on VirusTotal account
- Ensure no extra spaces in API key

### "Rate limit exceeded"
- Wait 1 minute before next scan
- Reduce number of emails per scan
- Increase RATE_LIMIT_DELAY in .env

### AI Model not loading
- Ensure `spam_model.pkl` and `vectorizer.pkl` are in project root
- Check file permissions
- Verify files are not corrupted

## 📝 API Usage Limits

### Gmail API (Free Tier)
- 1 billion quota units per day
- ~250 requests per user per second

### VirusTotal (Free Tier)
- 4 lookups/minute
- 500 lookups/day
- Max file size: 32MB

## 🤝 Contributing

This project is for educational purposes. Feel free to fork and modify for your needs.

## ⚠️ Disclaimer

- This tool is for educational and personal use only
- Always comply with Gmail's Terms of Service
- Respect VirusTotal's API usage guidelines
- Do not use for unauthorized access to others' emails
- The AI model's accuracy depends on training data quality

## 📄 License

This project is open source and available for educational purposes.

## 🙏 Acknowledgments

- Google Gmail API
- VirusTotal API
- Streamlit for the beautiful UI framework
- scikit-learn for machine learning capabilities

---

**Made with ❤️ for email security**

Need help? Check the troubleshooting section or create an issue!
