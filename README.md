# OSV CVE Vulnerability Dataset

A Python-based web scraping and data collection project for collecting publicly available CVE vulnerability information from the **Open Source Vulnerabilities (OSV)** database.

The project uses **BeautifulSoup** to scrape and parse vulnerability pages and **Pandas** to store and prepare the collected information for further data analysis.

---

## 📌 Project Overview

Cybersecurity vulnerabilities are continuously discovered in software, libraries, frameworks, and applications. The Common Vulnerabilities and Exposures (CVE) system provides unique identifiers for publicly known vulnerabilities.

This project collects CVE-related information from OSV and converts the scraped data into a structured CSV dataset.

The target is to collect approximately **2,000 valid CVE records**. A larger list of CVE IDs is used during collection because some CVEs may not have corresponding vulnerability pages on OSV.

---

## 🎯 Objectives

The main objectives of this project are:

- Collect CVE vulnerability data from OSV.
- Use **BeautifulSoup** for HTML parsing and web scraping.
- Create a structured CSV dataset.
- Collect approximately 2,000 valid CVE records.
- Clean and organize the collected data.
- Perform exploratory data analysis.
- Identify vulnerability trends and patterns.
- Analyze CVSS scores, severity, CWE, ecosystems, and affected packages.
- Publish the project and dataset on GitHub.

---

## 🌐 Data Source

The primary data source is:

**Open Source Vulnerabilities (OSV)**

https://osv.dev/

OSV provides publicly available vulnerability information from multiple sources.

Individual vulnerability pages contain information such as:

- CVE ID
- Published date
- Modified date
- Severity
- CVSS score
- CVSS vector
- Summary
- Detailed description
- Affected ecosystem
- Affected package
- Repository
- Affected ranges
- CWE
- CNA assigner
- References

---

## 🛠️ Technologies Used

### Programming Language

- Python 3

### Python Libraries

- `requests`
- `beautifulsoup4`
- `pandas`
- `csv`
- `time`
- `random`

### Development Tools

- Linux Terminal
- Python Virtual Environment
- Git
- GitHub

---

## 📂 Project Structure

```text
osv-cve-dataset/
│
├── data/
│   ├── cve_ids.txt
│   └── osv_cve_dataset.csv
│
├── src/
│   ├── get_cve_ids.py
│   └── collect_cves.py
│
├── requirements.txt
└── README.md