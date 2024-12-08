import asyncio
from dotenv import load_dotenv
from app.services.api_service import SecurityAPIService
import json

async def test_apis():
    # Load environment variables
    load_dotenv()
    
    # Initialize API service
    api_service = SecurityAPIService()
    
    # Test URLs (one known safe, one known malicious)
    test_urls = [
        "https://www.google.com",  # Known safe
        "http://malware.testing.google.test/testing/malware/"  # Test malicious URL
    ]
    
    for url in test_urls:
        print(f"\nTesting URL: {url}")
        print("-" * 50)
        
        try:
            results = await api_service.analyze_url(url)
            print("\nAPI Results:")
            print(json.dumps(results, indent=2))
            
            risk_score = api_service.calculate_risk_score(results)
            print(f"\nCalculated Risk Score: {risk_score}")
            
        except Exception as e:
            print(f"Error analyzing URL: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_apis())
