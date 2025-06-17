import sys
import requests
from urllib.parse import urlparse
from queue import Queue

def fuzz_web_application(file_path, target_url, allowed_status_codes, max_depth=3):
    banner = r"""
   ___ ____ ____ _  _ _  _ ____ 
    |  |___ |    |__| |\ | |  | 
    |  |___ |___ |  | | \| |__|                      
    """

    headings = ["URI", "Status Code", "Depth"]
    col_widths = [max(len(heading), 50) for heading in headings]
    uri_col_width = col_widths[0]
    status_code_width = 12  # Fixed width for the status code column
    depth_width = 6  # Fixed width for the depth column

    print(banner)
    print("\n")
    print("{:<{}}  {:>{}}  {:>{}}".format(headings[0], uri_col_width, headings[1], status_code_width, headings[2], depth_width))
    print("-" * (uri_col_width + status_code_width + depth_width + 4))

    # Use a queue to manage directories to scan
    scan_queue = Queue()
    # Set to track already visited paths
    visited_paths = set()
    
    # Start with root
    scan_queue.put(("", 0))  # (path, depth)
    
    # Load wordlist
    with open(file_path, 'r') as file:
        wordlist = [line.strip() for line in file if line.strip()]
    
    while not scan_queue.empty():
        current_path, current_depth = scan_queue.get()
        
        # Skip if max depth reached
        if current_depth > max_depth:
            continue
        
        # Avoid rescanning already visited paths
        if current_path in visited_paths:
            continue
        
        visited_paths.add(current_path)
        
        # Fuzz the current path with the wordlist
        for entry in wordlist:
            # Skip comments and empty lines
            if entry.startswith('#') or not entry:
                continue
                
            # Construct path
            if current_path:
                path = f"{current_path}/{entry}"
            else:
                path = entry
                
            # Construct full URL
            url = f"http://{target_url}/{path}"
            
            try:
                response = requests.get(url, stream=True, timeout=5)
                uri = urlparse(url).path  # Extract the URI from the URL
                status_code = str(response.status_code)

                if status_code in allowed_status_codes:
                    print("{:<{}}  {:>{}}  {:>{}}".format(uri, uri_col_width, status_code, status_code_width, current_depth, depth_width))
                    
                    # If we found a directory, add it to the queue for recursive scanning
                    if status_code == "200" and current_depth < max_depth:
                        # Detect if it's likely a directory (if response is HTML and contains links)
                        content_type = response.headers.get('content-type', '')
                        if 'text/html' in content_type and len(response.content) > 0:
                            scan_queue.put((path, current_depth + 1))
                            
            except requests.exceptions.RequestException:
                pass

    print("-" * (uri_col_width + status_code_width + depth_width + 4))
    print(f"Scan completed. Scanned {len(visited_paths)} directories up to depth {max_depth}.")

def is_likely_directory(response):
    """Check if a response is likely to be a directory listing"""
    content_type = response.headers.get('content-type', '')
    return 'text/html' in content_type and 'Index of' in response.text
