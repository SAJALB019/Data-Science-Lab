import requests
from bs4 import BeautifulSoup
import re
import time
import os

# ============================================================
# CONFIGURATION
# ============================================================

START_YEAR = 2020
END_YEAR = 2026
TARGET_IDS = 5000

OUTPUT_FILE = "data/cve_ids.txt"

BASE_URL = "https://github.com/CVEProject/cvelistV5/tree/main/cves"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/151.0 Safari/537.36"
}


# ============================================================
# START
# ============================================================

print("=" * 70)
print("COLLECTING CVE IDS WITH BEAUTIFULSOUP")
print("=" * 70)

print(f"Year range: {START_YEAR}-{END_YEAR}")
print(f"Target IDs: {TARGET_IDS}")
print()


cve_ids = set()


# ============================================================
# SCRAPE GITHUB YEAR DIRECTORIES
# ============================================================

for year in range(START_YEAR, END_YEAR + 1):

    print("-" * 70)
    print(f"Scraping year: {year}")
    print("-" * 70)

    url = f"{BASE_URL}/{year}"

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=30
        )

        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")

        if response.status_code != 200:
            print(f"ERROR: Could not access {year}")
            continue

        # ----------------------------------------------------
        # BEAUTIFULSOUP
        # ----------------------------------------------------

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # ----------------------------------------------------
        # FIND ALL LINKS
        # ----------------------------------------------------

        links = soup.find_all("a")

        year_count = 0

        for link in links:

            href = link.get("href", "")

            # Example GitHub directory:
            #
            # /CVEProject/cvelistV5/tree/main/cves/2024/1xxx
            #
            # We extract the numeric directory such as:
            # 1xxx
            # 2xxx
            # etc.

            pattern = rf"/CVEProject/cvelistV5/tree/main/cves/{year}/([^/]+)"

            match = re.search(pattern, href)

            if not match:
                continue

            directory = match.group(1)

            # Only numeric CVE ranges such as:
            #
            # 1xxx
            # 2xxx
            # 10xxx
            #
            if not re.fullmatch(r"\d+xxx", directory):
                continue

            # ------------------------------------------------
            # NOW REQUEST THE RANGE DIRECTORY
            # ------------------------------------------------

            range_url = (
                f"{BASE_URL}/{year}/{directory}"
            )

            try:

                range_response = requests.get(
                    range_url,
                    headers=HEADERS,
                    timeout=30
                )

                if range_response.status_code != 200:
                    continue

                range_soup = BeautifulSoup(
                    range_response.text,
                    "html.parser"
                )

                range_links = range_soup.find_all("a")

                for range_link in range_links:

                    range_href = range_link.get(
                        "href",
                        ""
                    )

                    # Look for CVE JSON files
                    #
                    # Example:
                    #
                    # CVE-2024-3094.json

                    cve_match = re.search(
                        rf"CVE-{year}-\d{{4,}}\.json",
                        range_href
                    )

                    if not cve_match:
                        continue

                    filename = cve_match.group(0)

                    cve_id = filename[:-5]

                    if cve_id not in cve_ids:

                        cve_ids.add(cve_id)

                        year_count += 1

                        # Stop once we have enough
                        if len(cve_ids) >= TARGET_IDS:
                            break

                print(
                    f"  {directory}: "
                    f"{year_count} CVEs collected"
                )

                # Stop range processing
                if len(cve_ids) >= TARGET_IDS:
                    break

                # Be gentle with GitHub
                time.sleep(1)

            except requests.RequestException as e:

                print(
                    f"  ERROR accessing {range_url}: {e}"
                )

        print()
        print(
            f"CVEs found for {year}: {year_count}"
        )

        print(
            f"Total unique CVEs: {len(cve_ids)}"
        )

        if len(cve_ids) >= TARGET_IDS:
            break

        # Delay between years
        time.sleep(2)

    except requests.RequestException as e:

        print(f"ERROR: {e}")


# ============================================================
# SORT CVE IDS
# ============================================================

cve_ids = sorted(
    cve_ids,
    key=lambda x: (
        int(x.split("-")[1]),
        int(x.split("-")[2])
    )
)


# ============================================================
# LIMIT TO TARGET
# ============================================================

selected_ids = cve_ids[:TARGET_IDS]


# ============================================================
# CREATE DATA DIRECTORY
# ============================================================

os.makedirs(
    os.path.dirname(OUTPUT_FILE),
    exist_ok=True
)


# ============================================================
# SAVE
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as f:

    for cve_id in selected_ids:

        f.write(
            cve_id + "\n"
        )


# ============================================================
# FINAL RESULT
# ============================================================

print()
print("=" * 70)
print("CVE ID COLLECTION COMPLETE")
print("=" * 70)

print(
    f"Total CVEs discovered: {len(cve_ids)}"
)

print(
    f"CVEs saved: {len(selected_ids)}"
)

print(
    f"Year range: {START_YEAR}-{END_YEAR}"
)

print(
    f"Saved to: {OUTPUT_FILE}"
)

print()

print("First 20 CVEs:")

for cve in selected_ids[:20]:
    print(f"  {cve}")

print()

print("Last 10 CVEs:")

for cve in selected_ids[-10:]:
    print(f"  {cve}")

print("=" * 70)