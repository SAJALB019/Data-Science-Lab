import csv
import os
import random
import time
import requests

from bs4 import BeautifulSoup


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = "data/cve_ids.txt"
OUTPUT_FILE = "data/osv_cve_dataset.csv"

TARGET_RECORDS = 2000

MIN_DELAY = 8
MAX_DELAY = 15

MAX_RETRIES = 8

BASE_URL = "https://osv.dev/vulnerability/"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/151.0 Safari/537.36"
    )
}


# ============================================================
# CSV COLUMNS
# ============================================================

FIELDNAMES = [
    "cve_id",
    "source",
    "import_source",
    "json_data",
    "aliases",
    "published",
    "modified",
    "severity",
    "cvss_score",
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
    "references",
]


# ============================================================
# LOAD CVE IDS
# ============================================================

def load_cve_ids():

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return []

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        ids = [
            line.strip()
            for line in f
            if line.strip()
        ]

    return ids


# ============================================================
# LOAD EXISTING CSV
# ============================================================

def load_existing():

    records = []
    collected = set()

    if not os.path.exists(OUTPUT_FILE):
        return records, collected

    print(
        f"Loading existing CSV: {OUTPUT_FILE}"
    )

    try:

        with open(
            OUTPUT_FILE,
            "r",
            encoding="utf-8",
            newline=""
        ) as f:

            reader = csv.DictReader(f)

            for row in reader:

                cve_id = row.get(
                    "cve_id",
                    ""
                ).strip()

                if cve_id:

                    records.append(row)
                    collected.add(cve_id)

    except Exception as e:

        print(
            f"ERROR loading existing CSV: {e}"
        )

    return records, collected


# ============================================================
# SAVE CSV
# ============================================================

def save_csv(records):

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES
        )

        writer.writeheader()

        writer.writerows(records)


# ============================================================
# GET TEXT
# ============================================================

def clean_text(element):

    if not element:
        return ""

    return " ".join(
        element.get_text(
            " ",
            strip=True
        ).split()
    )


# ============================================================
# GET DT/DD VALUE
# ============================================================

def get_detail_value(dl, label):

    if not dl:
        return ""

    for dt in dl.find_all("dt"):

        text = clean_text(dt)

        if text.lower() == label.lower():

            dd = dt.find_next_sibling("dd")

            if dd:
                return clean_text(dd)

    return ""


# ============================================================
# EXTRACT URL
# ============================================================

def get_detail_url(dl, label):

    if not dl:
        return ""

    for dt in dl.find_all("dt"):

        text = clean_text(dt)

        if text.lower() == label.lower():

            dd = dt.find_next_sibling("dd")

            if dd:

                link = dd.find("a")

                if link:
                    return link.get(
                        "href",
                        ""
                    )

    return ""


# ============================================================
# SCRAPE OSV PAGE
# ============================================================

def scrape_cve(cve_id):

    url = BASE_URL + cve_id

    print(
        f"\nRequesting: {url}"
    )

    for attempt in range(
        1,
        MAX_RETRIES + 1
    ):

        try:

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=30
            )

            print(
                f"Status Code: "
                f"{response.status_code}"
            )

            # ------------------------------------------------
            # RATE LIMIT
            # ------------------------------------------------

            if response.status_code == 429:

                retry_after = response.headers.get(
                    "Retry-After"
                )

                if retry_after:

                    try:
                        wait = int(
                            retry_after
                        )
                    except ValueError:
                        wait = random.randint(
                            30,
                            60
                        )

                else:

                    wait = min(
                        60 * attempt,
                        300
                    )

                print(
                    f"Rate limited (429). "
                    f"Waiting {wait} seconds..."
                )

                time.sleep(wait)

                continue

            # ------------------------------------------------
            # SERVER ERRORS
            # ------------------------------------------------

            if response.status_code >= 500:

                wait = min(
                    30 * attempt,
                    180
                )

                print(
                    f"Server error. "
                    f"Retrying in {wait} seconds..."
                )

                time.sleep(wait)

                continue

            # ------------------------------------------------
            # OTHER HTTP ERRORS
            # ------------------------------------------------

            if response.status_code != 200:

                print(
                    "ERROR: HTTP request failed"
                )

                return None

            # ------------------------------------------------
            # BEAUTIFULSOUP
            # ------------------------------------------------

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # ------------------------------------------------
            # VULNERABILITY PAGE
            # ------------------------------------------------

            vulnerability_page = soup.find(
                class_="vulnerability-page"
            )

            if not vulnerability_page:

                print(
                    "ERROR: Vulnerability page not found"
                )

                print(
                    "SKIPPED:",
                    cve_id
                )

                return None

            # ------------------------------------------------
            # CVE ID
            # ------------------------------------------------

            title = soup.find(
                "h1",
                class_="title"
            )

            found_cve = clean_text(
                title
            )

            if found_cve != cve_id:

                print(
                    "WARNING: CVE ID mismatch"
                )

                print(
                    "Expected:",
                    cve_id
                )

                print(
                    "Found:",
                    found_cve
                )

            # ------------------------------------------------
            # MAIN DETAILS
            # ------------------------------------------------

            dl = soup.find(
                "dl",
                class_="vulnerability-details"
            )

            if not dl:

                print(
                    "ERROR: vulnerability-details "
                    "not found"
                )

                return None

            # ------------------------------------------------
            # BASIC INFORMATION
            # ------------------------------------------------

            source = get_detail_url(
                dl,
                "Source"
            )

            import_source = get_detail_url(
                dl,
                "Import Source"
            )

            json_data = get_detail_url(
                dl,
                "JSON Data"
            )

            aliases = get_detail_value(
                dl,
                "Aliases"
            )

            published = get_detail_value(
                dl,
                "Published"
            )

            modified = get_detail_value(
                dl,
                "Modified"
            )

            severity = get_detail_value(
                dl,
                "Severity"
            )

            summary = get_detail_value(
                dl,
                "Summary"
            )

            details = get_detail_value(
                dl,
                "Details"
            )

            # ------------------------------------------------
            # CVSS
            # ------------------------------------------------

            cvss_score = ""
            cvss_version = ""
            cvss_vector = ""

            severity_element = None

            for dt in dl.find_all("dt"):

                if clean_text(dt).lower() == "severity":

                    severity_element = (
                        dt.find_next_sibling("dd")
                    )

                    break

            if severity_element:

                severity_text = clean_text(
                    severity_element
                )

                import re

                score_match = re.search(
                    r"(\d+\.\d+)\s*\(",
                    severity_text
                )

                if score_match:

                    cvss_score = (
                        score_match.group(1)
                    )

                version_match = re.search(
                    r"(CVSS_V[234])",
                    severity_text
                )

                if version_match:

                    cvss_version = (
                        version_match.group(1)
                    )

                vector_match = re.search(
                    r"(CVSS:\d+\.\d+/[A-Za-z0-9:/._-]+)",
                    severity_text
                )

                if vector_match:

                    cvss_vector = (
                        vector_match.group(1)
                    )

            # ------------------------------------------------
            # AFFECTED PACKAGES
            # ------------------------------------------------

            ecosystem = ""
            package = ""
            range_type = ""
            repo = ""
            introduced = ""
            fixed = ""

            package_section = soup.find(
                "osv-tabs",
                class_="vulnerability-packages"
            )

            if package_section:

                ecosystem_element = package_section.find(
                    class_="vuln-ecosystem"
                )

                package_element = package_section.find(
                    class_="vuln-name"
                )

                ecosystem = clean_text(
                    ecosystem_element
                )

                package = clean_text(
                    package_element
                )

                affected_heading = None

                for h3 in package_section.find_all(
                    "h3"
                ):

                    if "Affected ranges" in clean_text(h3):

                        affected_heading = h3
                        break

                if affected_heading:

                    subsection = (
                        affected_heading.find_parent(
                            class_="vulnerability-package-subsection"
                        )
                    )

                    if subsection:

                        affected_dl = subsection.find(
                            "dl"
                        )

                        if affected_dl:

                            range_type = get_detail_value(
                                affected_dl,
                                "Type"
                            )

                            repo = get_detail_value(
                                affected_dl,
                                "Repo"
                            )

                            events = None

                            for dt in affected_dl.find_all(
                                "dt"
                            ):

                                if clean_text(dt).lower() == "events":

                                    events = (
                                        dt.find_next_sibling(
                                            "dd"
                                        )
                                    )

                                    break

                            if events:

                                event_cells = events.find_all(
                                    class_="mdc-layout-grid__cell--span-9"
                                )

                                for i in range(
                                    0,
                                    len(event_cells)
                                ):

                                    text = clean_text(
                                        event_cells[i]
                                    )

                                    if i > 0:

                                        previous = clean_text(
                                            event_cells[i - 1]
                                        )

                                        if previous.lower() == "introduced":
                                            introduced = text

                                        elif previous.lower() == "fixed":
                                            fixed = text

            # ------------------------------------------------
            # DATABASE SPECIFIC
            # ------------------------------------------------

            cwe_ids = ""
            cna_assigner = ""

            specific_blocks = soup.find_all(
                "pre",
                class_="specific"
            )

            for block in specific_blocks:

                text = block.get_text(
                    strip=True
                )

                if "cwe_ids" in text:

                    match = re.findall(
                        r'"(CWE-\d+)"',
                        text
                    )

                    if match:

                        cwe_ids = "; ".join(
                            match
                        )

                if "cna_assigner" in text:

                    match = re.search(
                        r'"cna_assigner"\s*:\s*"([^"]+)"',
                        text
                    )

                    if match:

                        cna_assigner = (
                            match.group(1)
                        )

            # ------------------------------------------------
            # REFERENCES
            # ------------------------------------------------

            references = []

            for dt in dl.find_all("dt"):

                if clean_text(dt).lower() == "references":

                    dd = dt.find_next_sibling(
                        "dd"
                    )

                    if dd:

                        for link in dd.find_all(
                            "a",
                            href=True
                        ):

                            href = link.get(
                                "href"
                            )

                            if href:
                                references.append(
                                    href
                                )

                    break

            references_text = "; ".join(
                dict.fromkeys(
                    references
                )
            )

            # ------------------------------------------------
            # BUILD RECORD
            # ------------------------------------------------

            record = {

                "cve_id": cve_id,

                "source": source,

                "import_source": import_source,

                "json_data": json_data,

                "aliases": aliases,

                "published": published,

                "modified": modified,

                "severity": severity,

                "cvss_score": cvss_score,

                "cvss_version": cvss_version,

                "cvss_vector": cvss_vector,

                "summary": summary,

                "details": details,

                "ecosystem": ecosystem,

                "package": package,

                "range_type": range_type,

                "repo": repo,

                "introduced": introduced,

                "fixed": fixed,

                "cwe_ids": cwe_ids,

                "cna_assigner": cna_assigner,

                "references": references_text,
            }

            return record

        except requests.RequestException as e:

            print(
                f"Request error: {e}"
            )

            wait = min(
                30 * attempt,
                180
            )

            time.sleep(wait)

        except Exception as e:

            print(
                f"ERROR parsing {cve_id}: {e}"
            )

            return None

    return None


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("OSV CVE DATASET COLLECTOR")
    print("=" * 70)

    print(
        f"Target records: {TARGET_RECORDS}"
    )

    print(
        f"Input: {INPUT_FILE}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        f"Delay between requests: "
        f"{MIN_DELAY}-{MAX_DELAY} seconds"
    )

    print(
        f"Maximum retries: {MAX_RETRIES}"
    )

    print()

    # --------------------------------------------------------
    # LOAD IDS
    # --------------------------------------------------------

    cve_ids = load_cve_ids()

    print(
        f"CVE IDs available: {len(cve_ids)}"
    )

    if not cve_ids:

        print(
            "ERROR: No CVE IDs found."
        )

        return

    # --------------------------------------------------------
    # LOAD EXISTING DATA
    # --------------------------------------------------------

    records, collected = load_existing()

    print(
        f"Existing records: {len(records)}"
    )

    print(
        f"Already collected: {len(collected)}"
    )

    print()

    # --------------------------------------------------------
    # SCRAPE
    # --------------------------------------------------------

    for index, cve_id in enumerate(
        cve_ids,
        start=1
    ):

        # Stop at target
        if len(records) >= TARGET_RECORDS:

            print()
            print(
                "TARGET REACHED!"
            )

            break

        # Skip duplicates
        if cve_id in collected:

            continue

        print()
        print("-" * 70)

        print(
            f"[{index}/{len(cve_ids)}] "
            f"SCRAPING {cve_id}"
        )

        print(
            f"Dataset progress: "
            f"{len(records)}/{TARGET_RECORDS}"
        )

        print("-" * 70)

        record = scrape_cve(
            cve_id
        )

        if record:

            records.append(
                record
            )

            collected.add(
                cve_id
            )

            print()
            print(
                f"SUCCESS: {cve_id}"
            )

            print(
                f"Dataset: "
                f"{len(records)}/{TARGET_RECORDS}"
            )

            save_csv(
                records
            )

            print(
                "CSV saved."
            )

        else:

            print(
                f"FAILED/SKIPPED: {cve_id}"
            )

        # ----------------------------------------------------
        # DELAY
        # ----------------------------------------------------

        if len(records) < TARGET_RECORDS:

            delay = random.uniform(
                MIN_DELAY,
                MAX_DELAY
            )

            print(
                f"\nSleeping "
                f"{delay:.1f} seconds..."
            )

            try:

                time.sleep(
                    delay
                )

            except KeyboardInterrupt:

                print()
                print(
                    "Interrupted by user."
                )

                print(
                    "Saving current dataset..."
                )

                save_csv(
                    records
                )

                print(
                    f"Saved {len(records)} records."
                )

                return

    # --------------------------------------------------------
    # FINAL SAVE
    # --------------------------------------------------------

    save_csv(
        records
    )

    print()
    print("=" * 70)
    print("COLLECTION COMPLETE")
    print("=" * 70)

    print(
        f"Successful records: "
        f"{len(records)}"
    )

    print(
        f"Target: "
        f"{TARGET_RECORDS}"
    )

    print(
        f"CSV: "
        f"{OUTPUT_FILE}"
    )

    print("=" * 70)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()