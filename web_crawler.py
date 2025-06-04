import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def get_headers():
    return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

def crawl_recursive(url, depth=3, visited=None):
    if visited is None:
        visited = set()

    # If already visited, or if depth is negative (should not happen with current calls but good guard)
    if url in visited or depth < 0:
        return visited

    visited.add(url) # Add current URL to visited set

    if depth == 0: # If max depth is reached, don't crawl its children
        return visited

    try:
        # Assume get_headers() will be implemented later
        response = requests.get(url, headers=get_headers(), timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes

        # visited.add(url) # Moved up
        soup = BeautifulSoup(response.text, 'html.parser')

        for tag in soup.find_all('a', href=True):
            full_url = urljoin(url, tag["href"])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                crawl_recursive(full_url, depth - 1, visited)
    except Exception as e:
        print(f"Error crawling {url}: {e}")

    return visited

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple web crawler to find endpoints.")
    parser.add_argument("start_url", help="The URL to start crawling from.")
    parser.add_argument("output_file", help="File to save the discovered endpoints.")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default: 3).")
    args = parser.parse_args()

    print(f"Starting crawl from {args.start_url} with depth {args.depth}...")
    discovered_endpoints = crawl_recursive(args.start_url, args.depth)

    with open(args.output_file, 'w') as f:
        for endpoint in discovered_endpoints:
            f.write(endpoint + "\n")

    print(f"Crawling complete. Found {len(discovered_endpoints)} endpoints. Results saved to {args.output_file}")
