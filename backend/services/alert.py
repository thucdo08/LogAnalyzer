import os
import requests
from dotenv import load_dotenv

load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack(text: str):
    """Gửi thông báo Slack (im lặng nếu chưa cấu hình)."""
    if not SLACK_WEBHOOK_URL:
        print("⚠️ Chưa cấu hình Slack webhook.")
        return
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=5)
        if resp.status_code != 200:
            print(f"Lỗi gửi Slack: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Lỗi khi gửi Slack: {e}")