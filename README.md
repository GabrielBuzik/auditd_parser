# auditd_parser
Python code that parses Auditd logs, saves parsed events to SQLite and aggregates results for chosen rules/commands.

# Auditd Setup Guide

This guide provides step-by-step instructions to set up Auditd on Ubuntu, configure rules using keys in the needed file, and install Pandas for data analysis.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Install Auditd](#install-auditd)
- [Configure Auditd Rules](#configure-auditd-rules)
- [Install Pandas](#install-pandas)

## Prerequisites

- Ubuntu operating system (tested on Ubuntu XX.XX)
- Administrative access to the Ubuntu system

## Install Auditd

1. Update the package list for the most up-to-date information on available packages:

   ```bash
   sudo apt update
   ```
2. Install the Auditd package:
   ```bash
   sudo apt install auditd
   ```
3. Open the Audit rules file for editing:

   ```bash
   sudo su
   sudo nano /etc/audit/rules.d/audit.rules
   ```
## Configure Auditd Rules
1. Add the necessary audit rules using the appropriate keys. For example:

   ```bash
   -w /etc/cron.allow -p rxwa -k cron_allow
   -w /etc/cron.deny -p rxwa -k cron_deny
   -w /etc/cron.d/ -p rxwa -k cron_d
   -w /etc/cron.daily/ -p wa -k cron_daily
   -w /etc/cron.hourly/ -p wa -k cron_hourly
   -w /etc/cron.monthly/ -p wa -k cron_monthly
   -w /etc/cron.weekly/ -p wa -k cron
   -w /etc/crontab -p wa -k cron
   -w /var/spool/cron/ -p wa -k cron
   ```
2. Restart the Auditd service to apply the new rules:
   ```bash
   sudo service restart auditd
   ```
## Install Pandas
   Install Pandas(Can install in venv if you want)
   ```bash
   pip install pandas
   ```

## Run
  ```bash
   python3 main.py
   ```