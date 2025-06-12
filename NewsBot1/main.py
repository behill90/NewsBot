import os
import re
import json
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Set
import requests
import feedparser
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
import anthropic

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IOCExtractor:
    """Extract IOCs and IOAs from text"""

    def __init__(self):
        self.patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'file_path': re.compile(r'(?:[A-Za-z]:\\|/)[^\s<>"{}|\\^`\[\]]*'),
            'registry_key': re.compile(r'HKEY_[A-Z_]+\\[^\s<>"{}|\\^`\[\]]*', re.IGNORECASE),
            'cve': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
            'mutex': re.compile(r'(?:mutex|semaphore)[:\s]+[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            'process_name': re.compile(r'(?:process|executable)[:\s]+[^\s<>"{}|\\^`\[\]]+\.exe', re.IGNORECASE),
            'yara_rule': re.compile(r'rule\s+\w+\s*{[^}]*}', re.IGNORECASE | re.DOTALL),
        }

        self.false_positives = {
            'domain': {
                'example.com', 'test.com', 'localhost', 'domain.com', 'site.com',
                'google.com', 'microsoft.com', 'github.com', 'twitter.com'
            },
            'ip_address': {
                '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.1.1',
                '10.0.0.1', '172.16.0.1'
            },
            'email': {
                'example@example.com', 'test@test.com', 'admin@domain.com'
            }
        }

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        iocs = {}

        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                unique_matches = list(set(matches))
                if ioc_type in self.false_positives:
                    unique_matches = [m for m in unique_matches
                                      if m.lower() not in self.false_positives[ioc_type]]
                if ioc_type == 'domain':
                    unique_matches = self._filter_domains(unique_matches)
                elif ioc_type == 'ip_address':
                    unique_matches = self._filter_ips(unique_matches)

                if unique_matches:
                    iocs[ioc_type] = unique_matches

        return iocs

    def _filter_domains(self, domains: List[str]) -> List[str]:
        filtered = []
        for domain in domains:
            if (len(domain) > 4 and
                    not domain.endswith('.jpg') and
                    not domain.endswith('.png') and
                    not domain.endswith('.gif') and
                    not any(legit in domain.lower() for legit in ['github.com', 'microsoft.com', 'google.com'])):
                filtered.append(domain)
        return filtered

    def _filter_ips(self, ips: List[str]) -> List[str]:
        filtered = []
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    first_octet = int(parts[0])
                    second_octet = int(parts[1])

                    if not (
                            first_octet == 10 or
                            (first_octet == 172 and 16 <= second_octet <= 31) or  # 172.16.0.0/12
                            (first_octet == 192 and second_octet == 168) or  # 192.168.0.0/16
                            first_octet == 127 or
                            first_octet >= 224
                    ):
                        filtered.append(ip)
                except ValueError:
                    continue
        return filtered

    def format_iocs_for_slack(self, iocs: Dict[str, List[str]]) -> str:
        if not iocs:
            return ""

        ioc_section = "\n🚨 **INDICATORS OF COMPROMISE (IOCs):**\n"

        priority_order = ['cve', 'sha256', 'sha1', 'md5', 'ip_address', 'domain', 'url', 'email',
                          'file_path', 'registry_key', 'mutex', 'process_name', 'yara_rule']

        for ioc_type in priority_order:
            if ioc_type in iocs:
                values = iocs[ioc_type]
                if values:
                    type_name = ioc_type.replace('_', ' ').title()
                    if ioc_type == 'cve':
                        type_name = 'CVE'

                    ioc_section += f"\n**{type_name}:**\n"

                    display_values = values[:10]
                    for value in display_values:
                        if ioc_type in ['url', 'email', 'domain']:
                            ioc_section += f"• `{value}`\n"
                        else:
                            ioc_section += f"• `{value}`\n"

                    if len(values) > 10:
                        ioc_section += f"• ... and {len(values) - 10} more\n"

        return ioc_section

class ThreatIntelligenceBot:
    def __init__(self):

        self.slack_token = os.getenv('slack_bot_token')
        self.slack_channel = os.getenv('slack_channel', '#sec-news')
        self.slack_client = WebClient(token=self.slack_token) if self.slack_token else None

        self.claude_api_key = os.getenv('anthropic_api_key')
        self.claude_client = anthropic.Anthropic(api_key=self.claude_api_key) if self.claude_api_key else None

        self.tech_stack = {
            'aws', 'amazon web services', 'ec2', 's3', 'lambda', 'cloudformation',
            'google cloud', 'gcp', 'kubernetes', 'docker',
            'linux', 'macos', 'nixos',
            'mongodb', 'redis', 'github', 'jira', 'confluence', 'okta',
            'sumologic', 'crowdstrike', 'qualys', 'okta',
            'webflow'
        }

        self.threat_feeds = [
            'https://feeds.feedburner.com/eset/blog',
            'https://blog.malwarebytes.com/feed/',
            'https://www.crowdstrike.com/blog/feed/',
            'https://unit42.paloaltonetworks.com/feed/',
            'https://www.fireeye.com/blog/threat-research.xml',
            'https://www.cisa.gov/cybersecurity-advisories/all.xml',
            'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://krebsonsecurity.com/feed/',
            'https://www.bleepingcomputer.com/feed/',
            'https://www.securityweek.com/feed',
        ]

        self.processed_articles = set()
        self.load_processed_articles()

    def load_processed_articles(self):
        try:
            if os.path.exists('processed_articles.json'):
                with open('processed_articles.json', 'r') as f:
                    self.processed_articles = set(json.load(f))
        except Exception as e:
            logger.error(f"Error loading processed articles: {e}")
            self.processed_articles = set()

    def save_processed_articles(self):
        try:
            with open('processed_articles.json', 'w') as f:
                json.dump(list(self.processed_articles), f)
        except Exception as e:
            logger.error(f"Error saving processed articles: {e}")

    def fetch_feed_articles(self, feed_url: str, hours_back: int = 24) -> List[Dict]:
        articles = []
        try:
            logger.info(f"Fetching articles from: {feed_url}")

            feed = feedparser.parse(feed_url)

            if feed.bozo:
                logger.warning(f"Feed parsing warning for {feed_url}: {feed.bozo_exception}")

            time_threshold = datetime.now() - timedelta(hours=hours_back)

            for entry in feed.entries:
                try:
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])

                    if pub_date and pub_date < time_threshold:
                        continue

                    content = ""
                    if hasattr(entry, 'content') and entry.content:
                        content = entry.content[0].value
                    elif hasattr(entry, 'summary'):
                        content = entry.summary
                    elif hasattr(entry, 'description'):
                        content = entry.description

                    article = {
                        'id': entry.id if hasattr(entry, 'id') else entry.link,
                        'title': entry.title,
                        'link': entry.link,
                        'content': self.clean_html(content),
                        'published': pub_date.isoformat() if pub_date else None,
                        'source': feed.feed.title if hasattr(feed.feed, 'title') else feed_url
                    }

                    articles.append(article)

                except Exception as e:
                    logger.error(f"Error processing entry from {feed_url}: {e}")
                    continue

            logger.info(f"Fetched {len(articles)} articles from {feed_url}")

        except Exception as e:
            logger.error(f"Error fetching feed {feed_url}: {e}")

        return articles

    def clean_html(self, html_content: str) -> str:
        if not html_content:
            return ""

        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.get_text().strip()

    def extract_iocs(self, article: Dict) -> Dict:
        full_text = f"{article['title']} {article['content']}"
        return self.ioc_extractor.extract_iocs(full_text)

    def is_relevant_to_tech_stack(self, article: Dict) -> bool:
        text_to_search = f"{article['title']} {article['content']}".lower()

        for tech in self.tech_stack:
            if tech.lower() in text_to_search:
                logger.info(f"Article relevant due to tech: {tech}")
                return True

        high_priority_keywords = [
            'vulnerability', 'exploit', 'patch', 'security update',
            'breach', 'malware', 'ransomware', 'zero-day',
            'cve-', 'critical', 'emergency'
        ]

        for keyword in high_priority_keywords:
            if keyword in text_to_search:
                logger.info(f"Article relevant due to keyword: {keyword}")
                return True

        return False

    def summarize_with_claude(self, articles: List[Dict]) -> str:
        try:
            if not self.claude_client:
                logger.warning("Claude API client not configured, using fallback summarization")
                return self.fallback_summarization(articles)

            if not articles:
                return "No relevant threat intelligence articles found."

            all_iocs = {}
            articles_with_iocs = []

            articles_content = ""
            for i, article in enumerate(articles, 1):
                articles_content += f"ARTICLE {i}:\n"
                articles_content += f"Title: {article['title']}\n"
                articles_content += f"Source: {article['source']}\n"
                articles_content += f"Published: {article['published']}\n"
                articles_content += f"Link: {article['link']}\n"
                articles_content += f"Content: {article['content'][:3000]}{'...' if len(article['content']) > 3000 else ''}\n"
                articles_content += "\n" + "=" * 50 + "\n\n"

            prompt = f"""You are a cybersecurity analyst reviewing threat intelligence. Please analyze ALL {len(articles)} cybersecurity articles and provide a comprehensive summary for a security team.

Your analysis should include:
1. Executive Summary (2-3 sentences of key takeaways)
2. Critical Threats (highest priority items that need immediate attention)
3. Technology-Specific Impacts (group findings by affected technologies)
4. Complete Article List (ALL articles with titles and links)
5. Recommended Actions (specific, actionable next steps)
6. Threat Landscape Trends (if any patterns emerge)

Focus on:
- Include EVERY article found in your analysis
- Immediate security risks and vulnerabilities
- Actionable intelligence for defensive measures
- Clear prioritization of threats by severity
- Complete list of all articles with links
- Highlight any IOCs or IOAs (Indicators of Compromise or Attack) found in article for immediate blocking or monitoring.

IMPORTANT: IOCs and IOAs have been automatically extracted from the articles. Pay special attention to these indicators as they represent immediate actionable intelligencefor blocking, monitoring, or hunging.
Format the response for Slack (use markdown formatting with ** for bold, bullet points, etc.)

Here are ALL the articles to analyze:

{articles_content}

Please provide a thorough analysis that includes every single article found, with a complete list of titles and links that a CISO and security team can review."""

            response = self.claude_client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=4000,
                temperature=0.1,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            summary = response.content[0].text

            header = f"🚨 **Cybersecurity Threat Intelligence Report**\n"
            header += f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            header += f"📊 Analyzed {len(articles)} relevant articles\n"
            header += f"🤖 Analysis by Claude AI\n\n"

            ioc_summary = self.ioc_extractor.format_iocs_for_slack(all_iocs)

            return header + summary

        except Exception as e:
            logger.error(f"Error with Claude summarization: {e}")
            return self.fallback_summarization(articles)

    def fallback_summarization(self, articles: List[Dict]) -> str:
        if not articles:
            return "No relevant threat intelligence articles found."

        summary = f"🚨 **Cybersecurity Threat Intelligence Summary**\n"
        summary += f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"📊 Found {len(articles)} relevant articles\n\n"

        summary += f"**ALL RELEVANT ARTICLES:**\n\n"
        for i, article in enumerate(articles, 1):
            summary += f"**{i}. {article['title']}**\n"
            summary += f"🔗 Source: {article['source']}\n"
            summary += f"📄 {article['content'][:300]}...\n"
            summary += f"🌐 Link: {article['link']}\n\n"

        summary += "⚠️ Please review these threats and assess impact on our infrastructure."

        return summary

    def create_no_threats_summary(self, all_articles: List[Dict], hours_back: int) -> str:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        summary = f"✅ **Threat Intelligence Status: All Clear**\n\n"
        summary += f"📅 **Scan Completed:** {current_time}\n"
        summary += f"⏱️ **Time Period:** Last {hours_back} hours\n"
        summary += f"📊 **Articles Scanned:** {len(all_articles)} total articles\n"
        summary += f"🎯 **Relevant Threats:** 0 threats matching our tech stack\n\n"

        if all_articles:
            summary += f"**Sources Monitored:**\n"
            sources = set()
            for article in all_articles:
                sources.add(article.get('source', 'Unknown'))

            for source in sorted(sources):
                summary += f"• {source}\n"

            summary += f"\n**Sample Headlines (Not Relevant to Our Stack):**\n"
            for i, article in enumerate(all_articles[:3], 1):
                summary += f"{i}. {article['title'][:100]}{'...' if len(article['title']) > 100 else ''}\n"

            if len(all_articles) > 3:
                summary += f"... and {len(all_articles) - 3} more articles\n"
        else:
            summary += f"⚠️ **Note:** No articles found from any feeds. This could indicate:\n"
            summary += f"• Feed sources are down\n"
            summary += f"• Network connectivity issues\n"
            summary += f"• Very quiet period in cybersecurity news\n"

        summary += f"\n**Tech Stack Monitoring:**\n"
        tech_sample = list(self.tech_stack)[:10]
        for tech in tech_sample:
            summary += f"• {tech}\n"

        if len(self.tech_stack) > 10:
            summary += f"... and {len(self.tech_stack) - 10} more technologies\n"

        summary += f"\n**Next Scan:** {(datetime.now() + timedelta(hours=4)).strftime('%Y-%m-%d %H:%M:%S')} (estimated)\n"
        summary += f"🤖 **Automated by:** Threat Intelligence Bot\n"
        summary += f"💡 **Status:** System operational, monitoring continues"

        return summary

    def post_to_slack(self, summary: str):
        if not self.slack_client:
            logger.error("Slack client not configured")
            return False

        try:
            is_threat_alert = "🚨" in summary or "Critical Threats" in summary

            response = self.slack_client.chat_postMessage(
                channel=self.slack_channel,
                text=summary,
                unfurl_links=False,
                unfurl_media=False,
                thread_ts=None if is_threat_alert else None
            )

            logger.info(
                f"Posted {'threat alert' if is_threat_alert else 'status update'} to Slack channel: {self.slack_channel}")
            return True

        except SlackApiError as e:
            logger.error(f"Error posting to Slack: {e.response['error']}")
            return False

    def run(self, hours_back: int = 24):
        logger.info("Starting threat intelligence collection...")

        all_articles = []
        relevant_articles = []

        for feed_url in self.threat_feeds:
            articles = self.fetch_feed_articles(feed_url, hours_back)
            all_articles.extend(articles)
            time.sleep(1)

        logger.info(f"Total articles fetched: {len(all_articles)}")

        for article in all_articles:
            if article['id'] not in self.processed_articles:
                if self.is_relevant_to_tech_stack(article):
                    relevant_articles.append(article)
                    self.processed_articles.add(article['id'])

        logger.info(f"Relevant articles found: {len(relevant_articles)}")

        if all_articles and not relevant_articles:
            logger.info("No relevant articles found. Sample titles from feeds:")
            for i, article in enumerate(all_articles[:5]):
                logger.info(f"  {i + 1}. {article['title']}")
            logger.info("Consider updating your tech_stack keywords if these seem relevant")

        if relevant_articles:
            summary = self.summarize_with_claude(relevant_articles)

            if self.post_to_slack(summary):
                logger.info("Successfully posted threat intelligence summary")
            else:
                logger.error("Failed to post to Slack")
                print("\n" + "=" * 50)
                print("THREAT INTELLIGENCE SUMMARY")
                print("=" * 50)
                print(summary)
        else:
            no_threats_summary = self.create_no_threats_summary(all_articles, hours_back)
            if self.post_to_slack(no_threats_summary):
                logger.info("Posted 'no threats found' status to Slack")
            else:
                logger.error("Failed to post status to Slack")
                print(no_threats_summary)

        self.save_processed_articles()
        logger.info("Threat intelligence collection completed")


def main():
    bot = ThreatIntelligenceBot()
    bot.run(hours_back=24)


if __name__ == "__main__":
    main()