#!/usr/bin/env python3
"""
DEBUG VERSION - Cybersecurity Threat Intelligence Bot
This version includes extensive debug output to identify issues
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict
import requests
import feedparser
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging with more detail
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def debug_environment():
    """Debug environment variables and configuration."""
    print("\n" + "=" * 60)
    print("🔍 DEBUGGING ENVIRONMENT")
    print("=" * 60)

    slack_token = os.getenv('slack_bot_token')
    slack_channel = os.getenv('slack_channel', '#sec-news')
    claude_key = os.getenv('anthropic_api_key')

    print(f"✅ .env file loaded: {os.path.exists('.env')}")
    print(f"✅ slack_bot_token exists: {bool(slack_token)}")
    if slack_token:
        print(f"   Token format: {slack_token[:15]}...{slack_token[-5:] if len(slack_token) > 20 else slack_token}")
        print(f"   Starts with xoxb-: {slack_token.startswith('xoxb-')}")

    print(f"✅ slack_channel: {slack_channel}")
    print(f"✅ anthropic_api_key exists: {bool(claude_key)}")
    if claude_key:
        print(f"   Key format: {claude_key[:15]}...{claude_key[-5:] if len(claude_key) > 20 else claude_key}")

    return slack_token, slack_channel, claude_key


def test_slack_posting(slack_token, slack_channel):
    """Test if we can post to Slack."""
    print(f"\n🔍 TESTING SLACK CONNECTION")
    print("=" * 60)

    if not slack_token:
        print("❌ No Slack token found")
        return False

    if not slack_channel:
        print("❌ No Slack channel specified")
        return False

    try:
        client = WebClient(token=slack_token)

        # Test message
        test_message = f"🧪 **DEBUG TEST MESSAGE**\n"
        test_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        test_message += f"This is a test from the debug script to verify Slack integration."

        print(f"Attempting to post to channel: {slack_channel}")
        print(f"Test message: {test_message[:100]}...")

        response = client.chat_postMessage(
            channel=slack_channel,
            text=test_message,
            unfurl_links=False,
            unfurl_media=False
        )

        print(f"✅ SUCCESS: Message posted to Slack!")
        print(f"   Response timestamp: {response.get('ts')}")
        print(f"   Channel: {response.get('channel')}")
        return True

    except SlackApiError as e:
        print(f"❌ SLACK API ERROR: {e.response['error']}")
        print(f"   Full error: {e.response}")
        return False
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        return False


def test_feed_fetching():
    """Test if we can fetch articles from feeds."""
    print(f"\n🔍 TESTING FEED FETCHING")
    print("=" * 60)

    # Test with one simple feed
    test_feed = "https://feeds.feedburner.com/TheHackersNews"

    try:
        print(f"Testing feed: {test_feed}")
        feed = feedparser.parse(test_feed)

        print(f"✅ Feed parsed successfully")
        print(f"   Feed title: {getattr(feed.feed, 'title', 'No title')}")
        print(f"   Number of entries: {len(feed.entries)}")
        print(f"   Bozo (parsing issues): {feed.bozo}")

        if feed.entries:
            first_entry = feed.entries[0]
            print(f"   First article: {getattr(first_entry, 'title', 'No title')}")
            print(f"   Published: {getattr(first_entry, 'published', 'No date')}")

        return len(feed.entries) > 0

    except Exception as e:
        print(f"❌ ERROR fetching feed: {e}")
        return False


def test_tech_stack_filtering():
    """Test the tech stack filtering logic."""
    print(f"\n🔍 TESTING TECH STACK FILTERING")
    print("=" * 60)

    # Sample tech stack
    tech_stack = {'aws', 'windows', 'linux', 'apache', 'vulnerability', 'malware'}

    # Test articles
    test_articles = [
        {
            'title': 'Critical AWS S3 Vulnerability Discovered',
            'content': 'A new vulnerability in Amazon Web Services S3 buckets...'
        },
        {
            'title': 'New Malware Campaign Targets Windows Users',
            'content': 'Security researchers have identified a new malware strain...'
        },
        {
            'title': 'Sports News: Basketball Championship Results',
            'content': 'The basketball championship concluded with...'
        }
    ]

    def is_relevant(article):
        text = f"{article['title']} {article['content']}".lower()
        for tech in tech_stack:
            if tech.lower() in text:
                return True, tech
        return False, None

    relevant_count = 0
    for i, article in enumerate(test_articles, 1):
        relevant, matched_tech = is_relevant(article)
        print(f"   Article {i}: {'✅ RELEVANT' if relevant else '❌ NOT RELEVANT'}")
        print(f"      Title: {article['title']}")
        if relevant:
            print(f"      Matched tech: {matched_tech}")
            relevant_count += 1

    print(f"\nFiltering test: {relevant_count}/{len(test_articles)} articles would be relevant")
    return relevant_count > 0


def main():
    print("🚀 THREAT INTELLIGENCE BOT - DEBUG MODE")
    print("=" * 60)

    # Step 1: Check environment
    slack_token, slack_channel, claude_key = debug_environment()

    # Step 2: Test Slack
    slack_works = test_slack_posting(slack_token, slack_channel)

    # Step 3: Test feed fetching
    feeds_work = test_feed_fetching()

    # Step 4: Test filtering
    filtering_works = test_tech_stack_filtering()

    # Summary
    print(f"\n🏁 DEBUG SUMMARY")
    print("=" * 60)
    print(f"Environment setup: {'✅' if slack_token and slack_channel else '❌'}")
    print(f"Slack connection: {'✅' if slack_works else '❌'}")
    print(f"Feed fetching: {'✅' if feeds_work else '❌'}")
    print(f"Filtering logic: {'✅' if filtering_works else '❌'}")

    if all([slack_token, slack_channel, slack_works, feeds_work]):
        print(f"\n🎉 ALL TESTS PASSED!")
        print(f"Your threat intelligence bot should work correctly.")
        print(f"If the main script still doesn't post to Slack, the issue is likely:")
        print(f"  • No articles found in the time window")
        print(f"  • Articles don't match your tech stack")
        print(f"  • Rate limiting or temporary feed issues")
    else:
        print(f"\n❌ ISSUES FOUND - Fix these before running the main script:")
        if not slack_token:
            print(f"  • Add SLACK_BOT_TOKEN to .env file")
        if not slack_channel:
            print(f"  • Add SLACK_CHANNEL to .env file")
        if not slack_works:
            print(f"  • Fix Slack connection (check token, channel, permissions)")
        if not feeds_work:
            print(f"  • Check internet connection and feed availability")


if __name__ == "__main__":
    main()