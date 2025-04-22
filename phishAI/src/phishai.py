#!/usr/bin/env python3

import os
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

# Import analysis modules
from .analysis.security_analyzer import SecurityAnalyzer
from .utils.email_parser import EmailParser
from .utils.config import Config

# Initialize Typer app
app = typer.Typer()
console = Console()

def load_config() -> Config:
    """Load configuration from environment variables."""
    load_dotenv()
    return Config(
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY")
    )

def analyze_email(email_path: Path, config: Config, enable_ai: bool = True) -> None:
    """Analyze an email file using both AI and traditional methods."""
    try:
        # Parse the email
        parser = EmailParser()
        email_data = parser.parse_email(email_path)
        
        # Initialize security analyzer
        security_analyzer = SecurityAnalyzer(config.virustotal_api_key)
        
        # Perform security analysis
        with Progress() as progress:
            task = progress.add_task("[cyan]Performing security analysis...", total=100)
            security_results = security_analyzer.analyze(email_data)
            progress.update(task, completed=100)
        
        # Perform AI analysis if enabled and API key is available
        ai_results = None
        if enable_ai:
            try:
                from .analysis.ai_analyzer import AIAnalyzer
                if config.openai_api_key:
                    ai_analyzer = AIAnalyzer(config.openai_api_key)
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Performing AI analysis...", total=100)
                        ai_results = ai_analyzer.analyze(email_data)
                        progress.update(task, completed=100)
                else:
                    console.print("[yellow][!] OpenAI API key not found. Skipping AI analysis.[/yellow]")
            except ImportError:
                console.print("[yellow][!] AI analysis module not available. Skipping AI analysis.[/yellow]")
        
        # Display results
        display_results(email_data, ai_results, security_results)
        
    except Exception as e:
        console.print(f"[red][-] Error analyzing email: {str(e)}[/red]")
        sys.exit(1)

def display_results(email_data: dict, ai_results: Optional[dict], security_results: dict) -> None:
    """Display analysis results in a formatted way."""
    # Display email metadata
    console.print(Panel.fit(
        f"[bold]Subject:[/bold] {email_data['subject']}\n"
        f"[bold]From:[/bold] {email_data['sender']}\n"
        f"[bold]To:[/bold] {email_data['to']}\n"
        f"[bold]Date:[/bold] {email_data['date']}",
        title="Email Information"
    ))
    
    # Display AI Analysis if available
    if ai_results:
        console.print(Panel.fit(
            ai_results['analysis'],
            title="AI Analysis",
            border_style="green" if not ai_results['is_phishing'] else "red"
        ))
    
    # Display Security Analysis
    security_table = Table(title="Security Analysis")
    security_table.add_column("Check", style="cyan")
    security_table.add_column("Result", style="white")
    security_table.add_column("Status", style="green")
    
    for check, result in security_results.items():
        status = "✅" if result['status'] == 'safe' else "❌"
        security_table.add_row(
            check,
            result['details'],
            status
        )
    
    console.print(security_table)

@app.command()
def analyze(
    email_path: Path = typer.Argument(..., help="Path to the email file (.msg or .eml)"),
    ai_analysis: bool = typer.Option(True, help="Enable AI analysis (requires OpenAI API key)")
):
    """Analyze an email file for phishing indicators."""
    config = load_config()
    
    if not email_path.exists():
        console.print(f"[red][-] File not found: {email_path}[/red]")
        sys.exit(1)
    
    if email_path.suffix.lower() not in ['.msg', '.eml']:
        console.print("[red][-] Unsupported file format. Only .msg and .eml are supported.[/red]")
        sys.exit(1)
    
    analyze_email(email_path, config, enable_ai=ai_analysis)

if __name__ == "__main__":
    app() 