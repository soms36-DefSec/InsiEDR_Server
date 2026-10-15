# Insider Threat Scenario Detection API

## Overview

This service performs rule-based insider threat scenario detection using engineered behavioral features derived from the CERT Insider Threat Dataset.

The detector evaluates user activity across four domains:

* Logon Activity
* File Access Activity
* HTTP / Web Browsing Activity
* USB / Device Activity

The system does not perform machine learning inference. Instead, it detects predefined insider threat scenarios using behavioral rules derived from the CERT threat scenarios specification.

---

# API Endpoint

## POST /detect

Analyzes a user's feature vector and returns all matching insider-threat scenarios.

### Request

```json
{
  "logon_count": 12,
  "logoff_count": 12,
  "unique_pc_count": 5,
  "after_hours_logon": 1,
  "daily_after_hours_logon_ratio": 0.5,

  "file_access_count": 600,
  "daily_unique_filename_count": 250,

  "http_count": 100,
  "suspicious_url_count": 3,
  "file_sharing_site_visits": 8,

  "usb_connect_count": 12,
  "usb_disconnect_count": 12
}
```

All fields are optional.

Missing fields, null values, and NaN values are automatically handled and treated as zero.

### Response

```json
{
  "overall_score": 65,
  "overall_severity": "CRITICAL",
  "scenario_count": 3,
  "detections": [
    {
      "scenario": "Multi-PC Lateral Movement",
      "severity": "CRITICAL",
      "score": 25,
      "confidence": "VERY_HIGH",
      "reasons": [
        "unique_pc_count=5"
      ]
    }
  ]
}
```
# Input Schema

The detector accepts a single JSON object containing behavioral features for one user over the chosen analysis period (typically one day).

All fields are optional.

If a field is:

* Missing
* Null
* NaN

it is automatically treated as:

```json
0
```

However, for maximum detection coverage, all available features should be supplied.

---

## Complete Request Format

```json
{
  "logon_count": 0,
  "logoff_count": 0,
  "unique_pc_count": 0,
  "daily_unique_pc_count": 0,
  "after_hours_logon": 0,
  "daily_after_hours_logon_ratio": 0.0,
  "first_logon_time": 0,
  "last_logoff_time": 0,
  "weekend_logon": 0,
  "daily_pc_access_entropy": 0.0,

  "usb_connect_count": 0,
  "usb_disconnect_count": 0,
  "after_hours_usb_usage": 0,
  "daily_device_connect_count": 0,
  "daily_device_usage_flag": 0,
  "first_usb_usage_time": 0,
  "last_usb_usage_time": 0,

  "file_access_count": 0,
  "daily_unique_filename_count": 0,
  "daily_new_filename_count": 0,
  "daily_file_access_entropy": 0.0,
  "after_hours_file_access": 0,
  "weekend_file_access": 0,
  "daily_repeat_file_access_count": 0,
  "daily_repeat_file_ratio": 0.0,
  "first_file_access_time": 0,
  "last_file_access_time": 0,

  "http_count": 0,
  "daily_http_request_count": 0,
  "unique_url_count": 0,
  "suspicious_url_count": 0,
  "file_sharing_site_visits": 0,
  "job_search_site_visits": 0,
  "http_after_hours": 0,
  "daily_unique_domain_count": 0,
  "daily_new_domain_count": 0,
  "daily_domain_access_entropy": 0.0,
  "daily_external_domain_ratio": 0.0
}
```

---

# Field Definitions

## Logon Features

| Field                         | Type    | Description                         |
| ----------------------------- | ------- | ----------------------------------- |
| logon_count                   | integer | Number of successful logons         |
| logoff_count                  | integer | Number of logoffs                   |
| unique_pc_count               | integer | Number of distinct systems accessed |
| daily_unique_pc_count         | integer | Distinct systems accessed that day  |
| after_hours_logon             | integer | Number of after-hours logons        |
| daily_after_hours_logon_ratio | float   | After-hours logons / total logons   |
| first_logon_time              | integer | First logon hour (0-23)             |
| last_logoff_time              | integer | Last logoff hour (0-23)             |
| weekend_logon                 | integer | Weekend logon count                 |
| daily_pc_access_entropy       | float   | Diversity of accessed systems       |

---

## File Features

| Field                          | Type    | Description                        |
| ------------------------------ | ------- | ---------------------------------- |
| file_access_count              | integer | Total file accesses                |
| daily_unique_filename_count    | integer | Distinct files accessed            |
| daily_new_filename_count       | integer | Previously unseen files accessed   |
| daily_file_access_entropy      | float   | Diversity of file access patterns  |
| after_hours_file_access        | integer | After-hours file accesses          |
| weekend_file_access            | integer | Weekend file accesses              |
| daily_repeat_file_access_count | integer | Repeated file accesses             |
| daily_repeat_file_ratio        | float   | Repeated accesses / total accesses |
| first_file_access_time         | integer | First file access hour             |
| last_file_access_time          | integer | Last file access hour              |

---

## HTTP Features

| Field                       | Type    | Description                              |
| --------------------------- | ------- | ---------------------------------------- |
| http_count                  | integer | Total HTTP requests                      |
| daily_http_request_count    | integer | Daily HTTP requests                      |
| unique_url_count            | integer | Distinct URLs visited                    |
| suspicious_url_count        | integer | URLs classified as suspicious            |
| file_sharing_site_visits    | integer | Visits to Dropbox, Drive, OneDrive, etc. |
| job_search_site_visits      | integer | Visits to job-search websites            |
| http_after_hours            | integer | After-hours HTTP activity                |
| daily_unique_domain_count   | integer | Distinct domains visited                 |
| daily_new_domain_count      | integer | Previously unseen domains visited        |
| daily_domain_access_entropy | float   | Domain diversity score                   |
| daily_external_domain_ratio | float   | External domains / total domains         |

---

## Device Features

| Field                      | Type    | Description                 |
| -------------------------- | ------- | --------------------------- |
| usb_connect_count          | integer | USB insertion count         |
| usb_disconnect_count       | integer | USB removal count           |
| after_hours_usb_usage      | integer | After-hours USB usage count |
| daily_device_connect_count | integer | Device connection count     |
| daily_device_usage_flag    | integer | Binary device activity flag |
| first_usb_usage_time       | integer | First USB usage hour        |
| last_usb_usage_time        | integer | Last USB usage hour         |

---

# Minimum Fields Required Per Scenario

## After-Hours Midnight Access

```json
{
  "after_hours_logon": 1,
  "first_logon_time": 2,
  "logon_count": 4
}
```

---

## Multi-PC Lateral Movement

```json
{
  "unique_pc_count": 5,
  "daily_unique_pc_count": 5,
  "daily_pc_access_entropy": 2.0
}
```

---

## Short Repeated Sessions

```json
{
  "logon_count": 15,
  "logoff_count": 15
}
```

---

## Bulk File Collection

```json
{
  "file_access_count": 800,
  "daily_unique_filename_count": 300
}
```

---

## Anomalous File Access Pattern

```json
{
  "daily_file_access_entropy": 3.0,
  "daily_new_filename_count": 60,
  "daily_repeat_file_ratio": 0.1
}
```

---

## Credential File Hunting

```json
{
  "daily_new_filename_count": 100,
  "daily_unique_filename_count": 100,
  "daily_repeat_file_ratio": 0.1
}
```

---

## Cloud Storage Exfiltration

```json
{
  "file_sharing_site_visits": 8,
  "http_after_hours": 1
}
```

---

## Research on Dark Web Tools

```json
{
  "suspicious_url_count": 5,
  "unique_url_count": 5
}
```

---

## Personal Email File Forwarding

```json
{
  "file_sharing_site_visits": 10,
  "http_after_hours": 1,
  "daily_external_domain_ratio": 0.8
}
```

---

## Malware C2 Communication

```json
{
  "http_count": 150,
  "unique_url_count": 1,
  "suspicious_url_count": 1
}
```

---

## Tor Network Access Attempt

```json
{
  "suspicious_url_count": 2,
  "http_after_hours": 1
}
```

---

## Phishing Site Visit

```json
{
  "suspicious_url_count": 1,
  "unique_url_count": 1,
  "http_count": 1
}
```

---

## Repeated Short USB Connects

```json
{
  "usb_connect_count": 12,
  "usb_disconnect_count": 12
}
```

---

# Severity Levels

| Score Range | Severity |
| ----------- | -------- |
| 0 - 14      | LOW      |
| 15 - 29     | MEDIUM   |
| 30 - 59     | HIGH     |
| 60+         | CRITICAL |

---

# Supported Features

## Logon Features

```text
logon_count
logoff_count
unique_pc_count
daily_unique_pc_count
after_hours_logon
daily_after_hours_logon_ratio
first_logon_time
last_logoff_time
weekend_logon
daily_pc_access_entropy
```

## File Features

```text
file_access_count
daily_unique_filename_count
daily_new_filename_count
daily_file_access_entropy
after_hours_file_access
weekend_file_access
daily_repeat_file_access_count
daily_repeat_file_ratio
first_file_access_time
last_file_access_time
```

## HTTP Features

```text
http_count
daily_http_request_count
unique_url_count
suspicious_url_count
file_sharing_site_visits
job_search_site_visits
http_after_hours
daily_unique_domain_count
daily_new_domain_count
daily_domain_access_entropy
daily_external_domain_ratio
```

## Device Features

```text
usb_connect_count
usb_disconnect_count
after_hours_usb_usage
daily_device_connect_count
daily_device_usage_flag
first_usb_usage_time
last_usb_usage_time
```

---

# Implemented Scenarios

## Logon Scenarios

### After-Hours Midnight Access

Detects users performing logons during unusual overnight hours combined with after-hours activity.

Severity: HIGH

### Multi-PC Lateral Movement

Detects access from multiple machines in a short period, indicating possible lateral movement.

Severity: CRITICAL

### Normal Daily Login

Recognizes normal user login behavior.

Severity: LOW

### Short Repeated Sessions

Detects repeated login/logout activity that may indicate scripted or suspicious behavior.

Severity: HIGH

### Possible Account Sharing

Detects behavior consistent with shared credentials across multiple systems.

Severity: HIGH

---

## File Scenarios

### Bulk File Collection

Approximates large-scale file collection behavior using file access volume and unique file counts.

Severity: CRITICAL

### Normal Document Editing

Recognizes routine document usage patterns.

Severity: LOW

### Anomalous File Access Pattern

Detects unusually broad file exploration activity.

Severity: HIGH

### Credential File Hunting

Detects behavior consistent with searching for sensitive files across many locations.

Severity: CRITICAL

### Possible New Employee Onboarding

Recognizes exploratory file access patterns that may be legitimate onboarding activity.

Severity: LOW

---

## HTTP Scenarios

### Normal Work Browsing

Recognizes standard work-related browsing behavior.

Severity: LOW

### Cloud Storage Exfiltration

Detects potential uploads to cloud storage services during unusual periods.

Severity: CRITICAL

### Research on Dark Web Tools

Detects browsing activity involving suspicious or anonymization-related sites.

Severity: HIGH

### Personal Email File Forwarding

Detects patterns consistent with forwarding company information through personal services.

Severity: CRITICAL

### Malware C2 Communication

Detects beacon-like web activity characteristic of command-and-control traffic.

Severity: CRITICAL

### Online Training Course

Recognizes potentially legitimate training activity.

Severity: LOW

### Excessive Personal Browsing

Detects heavy personal browsing during working hours.

Severity: LOW

### Tor Network Access Attempt

Detects activity consistent with Tor-related browsing.

Severity: HIGH

### Social Media During Work Hours

Detects significant non-work browsing activity.

Severity: LOW

### Phishing Site Visit

Detects access patterns associated with phishing websites.

Severity: CRITICAL

---

## Device Scenarios

### Repeated Short USB Connects

Detects rapid repeated USB insertion/removal behavior.

Severity: HIGH

---

# Limitations

Several CERT scenarios cannot be implemented because the required features are not present in the available feature set.

Missing features include:

```text
remote_logon_count
session_duration_avg
session_duration_max
file_copy_count
file_write_count
file_delete_count
sensitive_file_access
large_file_transfer_count
usb_usage_duration
usb_file_transfer_count
large_usb_transfer
unique_usb_devices
upload_count
download_count
```

As a result, some CERT scenarios are implemented as approximations while others are intentionally excluded.

---

# Notes

* Multiple scenarios may trigger simultaneously.
* Detections are not mutually exclusive.
* The detector is designed to identify behavioral patterns rather than prove malicious intent.
* All scoring and scenario decisions are deterministic and explainable.
