from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import os
import requests
import json
import time
import base64
from urllib.parse import urlparse
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Load environment variables
load_dotenv()

app = Flask(__name__, 
           template_folder='app/templates',
           static_folder='app/static')

def check_virustotal(url):
    api_key = os.getenv('VIRUS_TOTAL_API_KEY')
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    headers = {
        "x-apikey": api_key
    }

    try:
        # First, submit the URL for scanning
        submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        scan_params = {'apikey': api_key, 'url': url}
        scan_response = requests.post(submit_url, data=scan_params)
        
        if scan_response.status_code != 200:
            return {"error": f"VirusTotal scan failed: {scan_response.text}"}

        # Get the scan results
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        report_params = {
            'apikey': api_key,
            'resource': url
        }
        
        # Wait briefly for the scan to process
        time.sleep(2)
        
        report_response = requests.get(report_url, params=report_params)
        
        if report_response.status_code != 200:
            return {"error": f"Failed to get report: {report_response.text}"}
            
        report_data = report_response.json()
        
        return {
            "malicious": report_data.get("positives", 0),
            "suspicious": 0,  # VT v2 API doesn't differentiate suspicious
            "clean": report_data.get("total", 0) - report_data.get("positives", 0),
            "total": report_data.get("total", 0),
            "scan_date": report_data.get("scan_date", ""),
            "permalink": report_data.get("permalink", "")
        }
        
    except Exception as e:
        return {"error": f"VirusTotal API error: {str(e)}"}

def check_google_safe_browsing(url):
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "suiguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload)
        if response.status_code == 200:
            data = response.json()
            return {
                "threats_found": len(data.get("matches", [])),
                "is_safe": "matches" not in data,
                "details": data.get("matches", [])
            }
    except Exception as e:
        return {"error": str(e)}
    
    return {"is_safe": True, "threats_found": 0}

def check_urlscan(url):
    api_key = os.getenv('URLSCAN_API_KEY')
    if not api_key:
        return {"error": "URLScan API key not configured"}

    # First, try to search for existing scans
    search_headers = {
        'API-Key': api_key,
    }
    
    try:
        # First check if we have an existing scan
        search_url = f'https://urlscan.io/api/v1/search/?q=page.url:"{url}"&size=1'
        search_response = requests.get(search_url, headers=search_headers)
        
        if search_response.status_code == 200:
            search_data = search_response.json()
            if search_data.get('results') and len(search_data['results']) > 0:
                result = search_data['results'][0]
                return {
                    "success": True,
                    "status": "existing",
                    "result_url": result.get('result'),
                    "screenshot": result.get('screenshot'),
                    "message": "Found existing scan results",
                    "risk_level": "info"
                }
    except Exception as e:
        print(f"Search error (non-critical): {str(e)}")

    # If no existing scan found or search failed, try to submit new scan
    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json',
    }
    
    data = {
        "url": url,
        "visibility": "public",
        "tags": ["suiguard"],
        "customagent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "referer": "https://www.google.com/",
        "country": "US"
    }
    
    try:
        # Submit new scan
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data,
            timeout=10
        )
        
        if response.status_code == 429:
            return {
                "success": False,
                "error": "Rate limit exceeded. Please try again later."
            }
            
        response_data = response.json()
        
        if response.status_code == 400:
            # If scan is prevented, try to get the domain reputation
            domain = urlparse(url).netloc
            reputation_url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
            rep_response = requests.get(reputation_url, headers=search_headers)
            
            if rep_response.status_code == 200:
                rep_data = rep_response.json()
                if rep_data.get('total', 0) > 0:
                    return {
                        "success": True,
                        "status": "known",
                        "message": "This appears to be a known website",
                        "domain_info": {
                            "total_scans": rep_data.get('total', 0),
                            "domain": domain
                        },
                        "risk_level": "low"
                    }
            
            return {
                "success": False,
                "status": "blocked",
                "message": response_data.get("message", "Scan prevented"),
                "description": response_data.get("description", "Unable to scan this URL"),
                "risk_level": "unknown"
            }
            
        elif response.status_code != 200:
            return {"error": f"Scan submission failed: {response.text}"}
            
        return {
            "success": True,
            "status": "submitted",
            "result_url": response_data.get("result"),
            "scan_id": response_data.get("uuid"),
            "api_url": response_data.get("api"),
            "message": "Scan submitted successfully"
        }
        
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"URLScan error: {str(e)}"}

def init_gemini():
    genai.configure(api_key=os.getenv('GOOGLE_GEMINI_API_KEY'))
    
    # Configure the model
    generation_config = {
        "temperature": 0.9,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
    }

    # Create the model
    model = genai.GenerativeModel(
        model_name="gemini-pro",
        generation_config=generation_config
    )
    
    return model

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "URL is required"}), 400

        results = {
            "url": url,
            "virustotal": check_virustotal(url),
            "google_safe_browsing": check_google_safe_browsing(url),
            "urlscan": check_urlscan(url)
        }
        
        # Calculate overall risk
        vt_result = results["virustotal"]
        gsb_result = results["google_safe_browsing"]
        
        risk_factors = []
        risk_score = 0
        
        if vt_result.get("malicious", 0) > 0:
            risk_score += 40
            risk_factors.append(f"{vt_result['malicious']} security vendors flagged this URL")
            
        if vt_result.get("suspicious", 0) > 0:
            risk_score += 20
            risk_factors.append(f"{vt_result['suspicious']} vendors found suspicious behavior")
            
        if gsb_result.get("threats_found", 0) > 0:
            risk_score += 40
            risk_factors.append("Google Safe Browsing detected threats")
            
        results["risk_score"] = min(risk_score, 100)
        results["risk_factors"] = risk_factors
        
        return jsonify(results)

    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500

@app.route('/submit-suspicious', methods=['POST'])
def submit_suspicious():
    data = request.get_json()
    url = data.get('url')
    description = data.get('description')
    
    # Here you would typically save to a database
    # For now, we'll just return a success response
    return jsonify({
        'status': 'success',
        'message': 'Thank you for helping keep the internet safe! Your submission has been recorded.'
    })

@app.route('/ask-assistant', methods=['POST'])
def ask_assistant():
    try:
        data = request.get_json()
        question = data.get('question')
        url = data.get('url', '')
        scan_results = data.get('scanResults', {})
        
        if not question:
            return jsonify({
                'error': 'Question is required',
                'status': 'error'
            }), 400
            
        # Initialize Gemini
        model = init_gemini()
        
        # Construct context-aware prompt with system instructions
        context = f"""You are SuiGuard Assistant, an expert cybersecurity analyst and educator with deep expertise in URL analysis, security threat detection, and digital protection. Your role is to help users understand security threats and develop better security practices.

Analyzing this situation:

URL: {url if url else 'No URL provided'}

Scan Results:
{json.dumps(scan_results, indent=2) if scan_results else 'No scan results available'}

User Question: {question}

Please provide a helpful, clear response focusing on:
1. Direct answers to the user's question
2. Security implications
3. Recommended actions
4. Additional precautions if needed

Remember to:
- Stay focused on security implications
- Be proactive in identifying potential risks
- Encourage good security habits
- Adapt explanations to user's apparent technical level
- Provide context for all recommendations
- Maintain a balance between thorough analysis and accessibility

Keep the response concise and user-friendly."""
        
        try:
            # Generate response
            response = model.generate_content(context)
            
            return jsonify({
                'response': response.text,
                'status': 'success'
            })
            
        except Exception as e:
            print(f"Gemini API Error: {str(e)}")  # Log the actual error
            return jsonify({
                'error': 'Failed to generate response',
                'status': 'error',
                'details': str(e)
            }), 500
            
    except Exception as e:
        print(f"Server Error: {str(e)}")  # Log the actual error
        return jsonify({
            'error': 'Server error occurred',
            'status': 'error',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)