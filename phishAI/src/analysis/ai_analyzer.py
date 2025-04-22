from typing import Dict, Optional
import openai
from rich.console import Console

console = Console()

class AIAnalyzer:
    """Handles AI-based analysis of emails using OpenAI's API."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI analyzer with an optional API key."""
        if api_key:
            openai.api_key = api_key
        else:
            console.print("[yellow][!] No OpenAI API key provided. AI analysis will be disabled.[/yellow]")
    
    def analyze(self, email_data: Dict) -> Dict:
        """Analyze email content using OpenAI's API."""
        if not openai.api_key:
            return {
                'is_phishing': False,
                'analysis': "AI analysis is disabled. No OpenAI API key provided.",
                'confidence': 0.0
            }
        
        try:
            # Format the email content for analysis
            email_content = f"""
            Subject: {email_data['subject']}
            From: {email_data['sender']}
            To: {email_data['to']}
            Date: {email_data['date']}
            Body: {email_data['body']}
            """
            
            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert in email security and phishing detection. Analyze the following email and determine if it's likely a phishing attempt."},
                    {"role": "user", "content": email_content}
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            # Parse the response
            analysis = response.choices[0].message.content
            
            # Determine if it's phishing based on the analysis
            is_phishing = "phishing" in analysis.lower() or "suspicious" in analysis.lower()
            
            return {
                'is_phishing': is_phishing,
                'analysis': analysis,
                'confidence': 0.8 if is_phishing else 0.2
            }
            
        except Exception as e:
            console.print(f"[red][-] Error during AI analysis: {str(e)}[/red]")
            return {
                'is_phishing': False,
                'analysis': f"Error during AI analysis: {str(e)}",
                'confidence': 0.0
            } 