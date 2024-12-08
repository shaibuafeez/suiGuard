import aiohttp
import asyncio
from typing import Dict, Any
import os
from datetime import datetime
import hashlib
import json

class SecurityAPIService:
    """
    Service class for handling URL security analysis using multiple APIs
    """
    
    def __init__(self):
        self.virus_total_api_key = os.getenv('VIRUS_TOTAL_API_KEY')
        self.google_safe_browsing_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY')

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL using multiple security analysis APIs in parallel
        """
        tasks = [
            self._check_virus_total(url),
            self._check_google_safe_browsing(url),
            self._check_urlscan(url)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            'virus_total': results[0] if not isinstance(results[0], Exception) else str(results[0]),
            'google_safe_browsing': results[1] if not isinstance(results[1], Exception) else str(results[1]),
            'urlscan': results[2] if not isinstance(results[2], Exception) else str(results[2]),
            'timestamp': datetime.utcnow().isoformat(),
            'url': url
        }

    def calculate_risk_score(self, api_results: Dict[str, Any]) -> float:
        """
        Calculate overall risk score based on API results
        Returns a score between 0 (safe) and 1 (high risk)
        """
        score = 0
        total_weight = 0
        
        # VirusTotal scoring (weight: 0.4)
        vt_result = api_results.get('virus_total', {})
        if isinstance(vt_result, dict) and 'error' not in vt_result:
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            if total > 0:
                score += 0.4 * (positives / total)
                total_weight += 0.4

        # Google Safe Browsing scoring (weight: 0.4)
        gsb_result = api_results.get('google_safe_browsing', {})
        if isinstance(gsb_result, dict) and 'error' not in gsb_result:
            if not gsb_result.get('safe', True):
                score += 0.4
            total_weight += 0.4

        # URLScan scoring (weight: 0.2)
        us_result = api_results.get('urlscan', {})
        if isinstance(us_result, dict) and 'error' not in us_result:
            malicious_score = us_result.get('malicious_score', 0)
            if malicious_score > 0:
                score += 0.2 * min(malicious_score / 100, 1)
            total_weight += 0.2

        # Normalize score if we have any valid results
        return score / total_weight if total_weight > 0 else 0.0

    async def _check_virus_total(self, url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal API v3
        Documentation: https://developers.virustotal.com/reference/scan-url
        """
        if not self.virus_total_api_key:
            return {'error': 'VirusTotal API key not configured'}

        try:
            # URL ID is created by base64 encoding the URL
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    'x-apikey': self.virus_total_api_key
                }
                
                # Get the analysis results
                async with session.get(
                    f'https://www.virustotal.com/api/v3/urls/{url_id}',
                    headers=headers
                ) as response:
                    if response.status == 404:
                        # URL hasn't been analyzed before, submit it
                        data = {'url': url}
                        async with session.post(
                            'https://www.virustotal.com/api/v3/urls',
                            headers=headers,
                            data=data
                        ) as scan_response:
                            if scan_response.status != 200:
                                return {'error': 'Failed to submit URL for scanning'}
                            return {'message': 'URL submitted for scanning', 'positives': 0, 'total': 0}
                    
                    result = await response.json()
                    if 'data' in result:
                        attributes = result['data']['attributes']
                        stats = attributes.get('last_analysis_stats', {})
                        return {
                            'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                            'total': sum(stats.values()),
                            'scan_date': attributes.get('last_analysis_date', ''),
                            'reputation': attributes.get('reputation', 0)
                        }
                    return {'error': 'Invalid response from VirusTotal'}
        except Exception as e:
            return {'error': str(e)}

    async def _check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing API
        """
        if not self.google_safe_browsing_key:
            return {'error': 'Google Safe Browsing API key not configured'}

        try:
            async with aiohttp.ClientSession() as session:
                api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}'
                
                data = {
                    'client': {
                        'clientId': 'suiguard',
                        'clientVersion': '1.0.0'
                    },
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
                
                async with session.post(api_url, json=data) as response:
                    result = await response.json()
                    matches = result.get('matches', [])
                    return {
                        'safe': len(matches) == 0,
                        'threats': [match.get('threatType') for match in matches]
                    }
        except Exception as e:
            return {'error': str(e)}

    async def _check_urlscan(self, url: str) -> Dict[str, Any]:
        """
        Check URL against URLScan.io API to get risk score
        """
        if not self.urlscan_api_key:
            return {'error': 'URLScan.io API key not configured'}

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'API-Key': self.urlscan_api_key,
                }
                
                # Search for existing results
                search_url = f'https://urlscan.io/api/v1/search/?q=page.url:"{url}"&size=1'
                async with session.get(search_url, headers=headers) as search_response:
                    if search_response.status == 200:
                        search_data = await search_response.json()
                        results = search_data.get('results', [])
                        if results:
                            score = results[0].get('verdicts', {}).get('overall', {}).get('score', 0)
                            return {
                                'status': 'completed',
                                'malicious_score': score
                            }
                    
                    return {
                        'status': 'no_results',
                        'malicious_score': 0
                    }

        except Exception as e:
            return {'error': f'URLScan error: {str(e)}'}
