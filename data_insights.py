import pandas as pd
import os

INPUT_FILE = "data/osv_cve_dataset_cleaned.csv"
OUTPUT_FILE = "data/data_insights.txt"

print("=" * 70)
print("DATA INSIGHT ANALYSIS")
print("=" * 70)

# ------------------------------------------------------------
# Load cleaned dataset
# ------------------------------------------------------------

if not os.path.exists(INPUT_FILE):
    print(f"ERROR: File not found: {INPUT_FILE}")
    print("Run the data cleaning script first.")
    exit()

df = pd.read_csv(INPUT_FILE)

print(f"\nDataset loaded successfully.")
print(f"Total records: {len(df)}")
print(f"Total attributes: {len(df.columns)}")


# ------------------------------------------------------------
# Prepare data
# ------------------------------------------------------------

# Convert CVSS score to numeric
df["cvss_score"] = pd.to_numeric(
    df["cvss_score"],
    errors="coerce"
)

# Convert published date
df["published"] = pd.to_datetime(
    df["published"],
    errors="coerce"
)

# Create publication year
df["publication_year"] = df["published"].dt.year


# ------------------------------------------------------------
# Store insights
# ------------------------------------------------------------

insights = []

insights.append("=" * 70)
insights.append("DATA INSIGHT REPORT")
insights.append("=" * 70)

insights.append(f"\nTotal CVE Records: {len(df)}")
insights.append(f"Total Attributes: {len(df.columns)}")


# ------------------------------------------------------------
# 1. Severity Distribution
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("1. SEVERITY DISTRIBUTION")
insights.append("-" * 70)

severity = (
    df["severity_clean"]
    .dropna()
    .value_counts()
)

if len(severity) > 0:

    for level, count in severity.items():

        percentage = (count / len(df)) * 100

        insights.append(
            f"{level}: {count} records ({percentage:.2f}%)"
        )

    most_common = severity.idxmax()

    insights.append(
        f"\nMost common severity: {most_common}"
    )

else:
    insights.append("No severity data available.")


# ------------------------------------------------------------
# 2. CVSS Score Analysis
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("2. CVSS SCORE ANALYSIS")
insights.append("-" * 70)

scores = df["cvss_score"].dropna()

if len(scores) > 0:

    insights.append(
        f"Average CVSS Score: {scores.mean():.2f}"
    )

    insights.append(
        f"Maximum CVSS Score: {scores.max():.2f}"
    )

    insights.append(
        f"Minimum CVSS Score: {scores.min():.2f}"
    )

    insights.append(
        f"Median CVSS Score: {scores.median():.2f}"
    )

else:
    insights.append("No CVSS score data available.")


# ------------------------------------------------------------
# 3. Publication Year Analysis
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("3. PUBLICATION YEAR ANALYSIS")
insights.append("-" * 70)

years = (
    df["publication_year"]
    .dropna()
    .astype(int)
    .value_counts()
    .sort_index()
)

if len(years) > 0:

    for year, count in years.items():

        insights.append(
            f"{year}: {count} CVEs"
        )

    highest_year = years.idxmax()

    insights.append(
        f"\nYear with most CVEs: "
        f"{highest_year} ({years.max()} records)"
    )

else:
    insights.append("No publication date data available.")


# ------------------------------------------------------------
# 4. CWE Analysis
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("4. TOP CWE CATEGORIES")
insights.append("-" * 70)

cwe_data = (
    df["cwe_ids"]
    .dropna()
    .astype(str)
    .str.split(";")
    .explode()
    .str.strip()
)

cwe_data = cwe_data[cwe_data != ""]

top_cwe = cwe_data.value_counts().head(10)

if len(top_cwe) > 0:

    for cwe, count in top_cwe.items():

        insights.append(
            f"{cwe}: {count} CVEs"
        )

else:
    insights.append("No CWE data available.")


# ------------------------------------------------------------
# 5. Ecosystem Analysis
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("5. SOFTWARE ECOSYSTEM ANALYSIS")
insights.append("-" * 70)

ecosystems = (
    df["ecosystem"]
    .dropna()
    .astype(str)
    .str.strip()
)

ecosystems = ecosystems[ecosystems != ""]

top_ecosystems = ecosystems.value_counts().head(10)

if len(top_ecosystems) > 0:

    for ecosystem, count in top_ecosystems.items():

        insights.append(
            f"{ecosystem}: {count} CVEs"
        )

else:
    insights.append("No ecosystem data available.")


# ------------------------------------------------------------
# 6. Package Analysis
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("6. TOP AFFECTED PACKAGES")
insights.append("-" * 70)

packages = (
    df["package"]
    .dropna()
    .astype(str)
    .str.strip()
)

packages = packages[packages != ""]

top_packages = packages.value_counts().head(10)

if len(top_packages) > 0:

    for package, count in top_packages.items():

        insights.append(
            f"{package}: {count} CVEs"
        )

else:
    insights.append("No package data available.")


# ------------------------------------------------------------
# 7. Data Completeness
# ------------------------------------------------------------

insights.append("\n" + "-" * 70)
insights.append("7. DATA COMPLETENESS")
insights.append("-" * 70)

for column in df.columns:

    missing = df[column].isna().sum()

    available = len(df) - missing

    percentage = (
        available / len(df) * 100
        if len(df) > 0
        else 0
    )

    insights.append(
        f"{column}: "
        f"{available}/{len(df)} available "
        f"({percentage:.2f}%)"
    )


# ------------------------------------------------------------
# 8. Key Findings
# ------------------------------------------------------------

insights.append("\n" + "=" * 70)
insights.append("KEY FINDINGS")
insights.append("=" * 70)

if len(severity) > 0:
    insights.append(
        f"• Most common severity: {severity.idxmax()}"
    )

if len(scores) > 0:
    insights.append(
        f"• Average CVSS score: {scores.mean():.2f}"
    )

if len(years) > 0:
    insights.append(
        f"• Highest publication year: "
        f"{years.idxmax()}"
    )

if len(top_cwe) > 0:
    insights.append(
        f"• Most common CWE: {top_cwe.index[0]}"
    )

if len(top_ecosystems) > 0:
    insights.append(
        f"• Most common ecosystem: "
        f"{top_ecosystems.index[0]}"
    )


# ------------------------------------------------------------
# Print results
# ------------------------------------------------------------

result = "\n".join(insights)

print(result)


# ------------------------------------------------------------
# Save results
# ------------------------------------------------------------

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
    file.write(result)

print("\n" + "=" * 70)
print("DATA INSIGHT ANALYSIS COMPLETE")
print("=" * 70)
print(f"Results saved to: {OUTPUT_FILE}")