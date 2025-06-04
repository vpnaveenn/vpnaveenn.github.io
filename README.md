# Simple Web Crawler

This script is a simple web crawler that starts from a given URL and recursively explores links up to a specified depth, collecting all unique URLs found within the same domain. The discovered endpoints are then saved to a text file.

## Features

- Crawls a website starting from a specific URL.
- Limits crawl depth to prevent infinite loops or excessive crawling.
- Restricts crawling to the same domain as the starting URL.
- Saves discovered endpoints to a user-specified output file.
- Uses a common User-Agent to mimic a browser request.

## Requirements

- Python 3.x
- `requests`
- `beautifulsoup4`

## Installation

1. Clone this repository (or download the `web_crawler.py` and `requirements.txt` files).
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script from the command line:

```bash
python web_crawler.py <start_url> <output_file> [--depth <max_depth>]
```

### Arguments

- `start_url`: The URL to begin crawling from (e.g., `http://example.com`).
- `output_file`: The path to the file where discovered endpoints will be saved (e.g., `endpoints.txt`).
- `--depth <max_depth>` (optional): The maximum depth to crawl. Defaults to 3 if not specified.

### Example

```bash
python web_crawler.py http://example.com found_links.txt --depth 2
```

This command will start crawling from `http://example.com`, go up to 2 levels deep, and save all unique URLs found within `example.com` to `found_links.txt`.
