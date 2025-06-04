import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

def get_headers():
    return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

def crawl_recursive(url, original_domain_netloc, depth=3, visited=None):
    if visited is None:
        visited = set()

    # If already visited, or if depth is negative
    if url in visited or depth < 0:
        # No print here, as this is a common base case for recursion termination.
        # Or, if preferred: print(f"[Depth: {depth}] Skipping (already visited or invalid depth): {url}")
        return visited

    print(f"[Depth: {depth}] Processing: {url}")
    # visited.add(url) will be moved to after successful fetch + parsing eligibility

    if depth == 0: # If max depth is reached, don't crawl its children from this page
        print(f"  Max depth reached at {url}, not crawling further from here.")
        # Add to visited here if we consider reaching it "visiting", even if not crawled from
        if url not in visited: visited.add(url)
        return visited

    max_retries = 3
    retry_delay_seconds = 5
    response = None
    attempts = 0

    while attempts < max_retries:
        try:
            response = requests.get(url, headers=get_headers(), timeout=30)
            response.raise_for_status()
            print(f"  Successfully fetched {url} on attempt {attempts + 1}")
            break
        except requests.exceptions.Timeout:
            print(f"  Attempt {attempts + 1} of {max_retries} timed out for {url}. Retrying in {retry_delay_seconds}s...")
        except requests.exceptions.ConnectionError:
            print(f"  Attempt {attempts + 1} of {max_retries} connection error for {url}. Retrying in {retry_delay_seconds}s...")
        except requests.exceptions.HTTPError as e:
            print(f"  HTTP error {e.response.status_code} for {url} on attempt {attempts + 1}. Won't retry.")
            response = None
            break

        attempts += 1
        if attempts < max_retries:
            time.sleep(retry_delay_seconds)
        else:
            print(f"  All {max_retries} attempts failed for {url}.")
            response = None

    if response:
        try:
            # Add URL to visited only on successful fetch and before parsing/recursion
            visited.add(url)

            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)

            if links:
                print(f"  Found {len(links)} <a> tags with href in {url}")
            else:
                print(f"  No <a> tags with href found in {url}")
                return visited # No links to process further from this page

            for tag in links:
                full_url = urljoin(url, tag["href"])
                parsed_full_url = urlparse(full_url)

                print(f"  Raw link found: {tag['href']} -> Full URL: {full_url}")

                if full_url in visited:
                    print(f"  Skipping (already visited/processing): {full_url}")
                elif not parsed_full_url.netloc.endswith(original_domain_netloc):
                    print(f"  Skipping (different domain '{parsed_full_url.netloc}' vs original '{original_domain_netloc}'): {full_url}")
                else:
                    print(f"  Queuing for crawl: {full_url}")
                    crawl_recursive(full_url, original_domain_netloc, depth - 1, visited)
        except Exception as e:
            print(f"  Error parsing or processing content from {url}: {e}")
    else:
        print(f"  Failed to fetch {url} after retries. Skipping further processing of this URL.")
        # Ensure URL is not in visited if fetch ultimately failed, unless added at depth 0
        # Current logic: if depth == 0, it's added. If fetch fails, it's not added here.
        # This seems fine.

    return visited

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple web crawler to find endpoints.")
    parser.add_argument("start_url", help="The URL to start crawling from.")
    parser.add_argument("output_file", help="File to save the discovered endpoints.")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default: 3).")
    args = parser.parse_args()

    parsed_start_url = urlparse(args.start_url)
    original_netloc = parsed_start_url.netloc
    if original_netloc.startswith("www."):
        original_netloc = original_netloc[4:]

    print(f"Starting crawl from {args.start_url} (domain: {original_netloc}) with depth {args.depth}...")
    discovered_endpoints = crawl_recursive(args.start_url, original_netloc, args.depth)

    with open(args.output_file, 'w') as f:
        for endpoint in discovered_endpoints:
            f.write(endpoint + "\n")

    print(f"Crawling complete. Found {len(discovered_endpoints)} endpoints. Results saved to {args.output_file}")
