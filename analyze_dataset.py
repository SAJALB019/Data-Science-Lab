import pandas as pd
import os

INPUT_FILE = "data/osv_cve_dataset.csv"
CLEAN_FILE = "data/osv_cve_dataset_cleaned.csv"


print("=" * 70)
print("CVE DATASET - CLEANING AND DATA INSIGHTS")
print("=" * 70)


# ---------------------------------------------------------
# 1. LOAD DATA
# ---------------------------------------------------------

print("\n[1] Loading dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Original rows: {len(df)}")
print(f"Original columns: {len(df.columns)}")


# ---------------------------------------------------------
# 2. REMOVE COMPLETELY EMPTY ROWS
# ---------------------------------------------------------

print("\n[2] Removing completely empty rows...")

before = len(df)

df = df.dropna(how="all")

after = len(df)

print(f"Removed rows: {before - after}")


# ---------------------------------------------------------
# 3. REMOVE DUPLICATE CVE IDs
# ---------------------------------------------------------

print("\n[3] Removing duplicate CVE IDs...")

before = len(df)

df = df.drop_duplicates(subset=["cve_id"], keep="first")

after = len(df)

print(f"Duplicate rows removed: {before - after}")


# ---------------------------------------------------------
# 4. CLEAN TEXT COLUMNS
# ---------------------------------------------------------

print("\n[4] Cleaning text fields...")

text_columns = [
    "cve_id",
    "source",
    "import_source",
    "json_data",
    "aliases",
    "severity",
    "cvss_version",
    "cvss_vector",
    "summary",
    "details",
    "ecosystem",
    "package",
    "range_type",
    "repo",
    "introduced",
    "fixed",
    "cwe_ids",
    "cna_assigner",
    "references"
]

for column in text_columns:

    if column in df.columns:

        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
            .str.strip()
        )


# ---------------------------------------------------------
# 5. NORMALIZE EMPTY VALUES
# ---------------------------------------------------------

print("\n[5] Normalizing missing values...")

df = df.replace(
    ["", "EMPTY", "None", "nan", "NaN"],
    pd.NA
)


# ---------------------------------------------------------
# 6. CONVERT DATE COLUMNS
# ---------------------------------------------------------

print("\n[6] Converting date columns...")

df["published"] = pd.to_datetime(
    df["published"],
    errors="coerce",
    utc=True
)

df["modified"] = pd.to_datetime(
    df["modified"],
    errors="coerce",
    utc=True
)


# ---------------------------------------------------------
# 7. CONVERT CVSS SCORE TO NUMERIC
# ---------------------------------------------------------

print("\n[7] Converting CVSS scores...")

df["cvss_score"] = pd.to_numeric(
    df["cvss_score"],
    errors="coerce"
)


# ---------------------------------------------------------
# 8. STANDARDIZE SEVERITY
# ---------------------------------------------------------

print("\n[8] Standardizing severity...")

def clean_severity(value):

    if pd.isna(value):
        return pd.NA

    value = str(value).strip()

    if "(" in value:
        value = value.split("(")[-1].replace(")", "")

    return value.strip().upper()


df["severity_clean"] = df["severity"].apply(clean_severity)


# ---------------------------------------------------------
# 9. NORMALIZE ECOSYSTEM
# ---------------------------------------------------------

if "ecosystem" in df.columns:

    df["ecosystem"] = (
        df["ecosystem"]
        .astype("string")
        .str.strip()
    )


# ---------------------------------------------------------
# 10. VALIDATE CVE IDs
# ---------------------------------------------------------

print("\n[9] Validating CVE IDs...")

cve_pattern = r"^CVE-\d{4}-\d{4,}$"

valid_cves = df["cve_id"].str.match(
    cve_pattern,
    na=False
)

print(f"Valid CVE IDs: {valid_cves.sum()}")
print(f"Invalid CVE IDs: {(~valid_cves).sum()}")


# ---------------------------------------------------------
# 11. DATASET QUALITY
# ---------------------------------------------------------

print("\n[10] Dataset quality statistics")

print("\nMissing values:")
print(df.isna().sum())

print("\nDuplicate CVE IDs:")
print(df["cve_id"].duplicated().sum())


# ---------------------------------------------------------
# 12. DATA INSIGHTS
# ---------------------------------------------------------

print("\n")
print("=" * 70)
print("DATA INSIGHTS")
print("=" * 70)


# Total CVEs

print("\n1. Total CVEs:")
print(len(df))


# Severity

print("\n2. CVEs by Severity:")
print(
    df["severity_clean"]
    .value_counts(dropna=False)
)


# Average CVSS

print("\n3. Average CVSS Score:")

print(
    round(df["cvss_score"].mean(), 2)
)


# Highest CVSS

print("\n4. Highest CVSS Score:")

print(
    df["cvss_score"].max()
)


# CVEs by year

print("\n5. CVEs by Publication Year:")

df["published_year"] = df["published"].dt.year

print(
    df["published_year"]
    .value_counts()
    .sort_index()
)


# CWE

print("\n6. Top CWE Categories:")

print(
    df["cwe_ids"]
    .dropna()
    .value_counts()
    .head(10)
)


# Ecosystem

print("\n7. Top Ecosystems:")

print(
    df["ecosystem"]
    .dropna()
    .value_counts()
    .head(10)
)


# Packages

print("\n8. Top Affected Packages:")

print(
    df["package"]
    .dropna()
    .value_counts()
    .head(10)
)


# ---------------------------------------------------------
# 13. SAVE CLEAN DATASET
# ---------------------------------------------------------

print("\n")
print("=" * 70)
print("SAVING CLEANED DATASET")
print("=" * 70)

df.to_csv(
    CLEAN_FILE,
    index=False
)

print(f"\nCleaned dataset saved to:")
print(CLEAN_FILE)

print("\nFinal rows:", len(df))
print("Final columns:", len(df.columns))

print("\nDONE.")