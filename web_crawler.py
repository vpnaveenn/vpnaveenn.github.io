import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

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
    visited.add(url) # Add current URL to visited set, as it's now being processed.

    if depth == 0: # If max depth is reached, don't crawl its children from this page
        print(f"  Max depth reached at {url}, not crawling further from here.")
        return visited

    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        response.raise_for_status()

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
                # Depth check for the *next* call is implicitly handled by that call's entry conditions
                print(f"  Queuing for crawl: {full_url}")
                crawl_recursive(full_url, original_domain_netloc, depth - 1, visited)

    except requests.exceptions.RequestException as e:
        print(f"Error during requests to {url}: {e}")
    except Exception as e:
        print(f"Error crawling or parsing {url}: {e}")

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
