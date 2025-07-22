#!/usr/bin/env python3
import os
import json
import smtplib
import subprocess
from datetime import datetime, timezone
from email.message import EmailMessage

def load_config():
    return {
        "smtp_server": os.getenv("SMTP_SERVER"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "smtp_user": os.getenv("SMTP_USER"),
        "smtp_password": os.getenv("SMTP_PASSWORD"),
        "email_from": os.getenv("EMAIL_FROM"),
        "email_to": os.getenv("EMAIL_TO").split(","),
        "warning_days": int(os.getenv("WARNING_DAYS", "30")),
    }

def get_certificates():
    try:
        cmd = [
            "kubectl", "get", "certificates",
            "--all-namespaces",
            "-o", "json"
        ]
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout).get("items", [])
    except subprocess.CalledProcessError as e:
        print(f"Error getting certificates: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing certificate data: {e}")
        return []

def check_renewal(cert, warning_days):
    not_after = cert["status"]["notAfter"]
    expiry_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    days_remaining = (expiry_date - datetime.now(timezone.utc)).days

    return {
        "name": cert["metadata"]["name"],
        "namespace": cert["metadata"]["namespace"],
        "dns_names": cert["spec"]["dnsNames"],
        "expiry_date": expiry_date,
        "days_remaining": days_remaining,
        "needs_renewal": days_remaining <= warning_days
    }

def generate_report(expiring_certs):
    if not expiring_certs:
        return "No certificates require renewal at this time."

    report = ["️Certificate Renewal Alert - Expiring Soon:\n"]
    for cert in sorted(expiring_certs, key=lambda x: x['days_remaining']):
        report.append(
            f"{cert['name']} (Namespace: {cert['namespace']})\n"
            f"   Domains: {', '.join(cert['dns_names'])}\n"
            f"   Expires: {cert['expiry_date'].strftime('%Y-%m-%d')} "
            f"(in {cert['days_remaining']} days)\n"
        )
    return "\n".join(report)

def send_email(config, expiring_certs, report):
    msg = EmailMessage()
    msg["Subject"] = f"Certificate Renewal Alert - {len(expiring_certs)} certs expiring"
    msg["From"] = config["email_from"]
    msg["To"] = ", ".join(config["email_to"])
    msg.set_content(report)

    with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
        server.starttls()
        server.login(config["smtp_user"], config["smtp_password"])
        server.send_message(msg)

def main():
    cfg = load_config()
    certificates = get_certificates()

    expiring_certs = []
    for cert in certificates:
        if "status" not in cert or "notAfter" not in cert["status"]:
            continue

        cert_info = check_renewal(cert, cfg["warning_days"])
        if cert_info["needs_renewal"]:
            expiring_certs.append(cert_info)

    report = generate_report(expiring_certs)
    print(report)  # Log to stdout

    if expiring_certs:
        send_email(cfg, expiring_certs, report)

if __name__ == "__main__":
    main()