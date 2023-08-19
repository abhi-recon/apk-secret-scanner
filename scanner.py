import sys
import os
import subprocess
import re
import time

regex = {
    'google_api_key': r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
}

def decompile_apk(apk_path, output_dir, verbose=False):
    try:
        start_time = time.time()
        subprocess.run(['jadx', '-d', output_dir, apk_path], check=True)
        end_time = time.time()
        elapsed_time = end_time - start_time
        if verbose:
            print(f"Decompilation complete in {elapsed_time:.2f} seconds. Output stored in '{output_dir}'")
    except subprocess.CalledProcessError as e:
        print(f"Decompilation failed: {e}")
        sys.exit(1)

def scan_for_secrets(output_dir, verbose=False):
    secrets_found = False
    found_secrets = {}
    
    for root, _, files in os.walk(output_dir):
        for filename in files:
            if filename.endswith('.xml'):
                full_path = os.path.join(root, filename)
                with open(full_path, 'r') as f:
                    lines = f.readlines()
                    content = ''.join(lines)
                    for key, pattern in regex.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            secret_value = match.group()
                            line_number = content.count('\n', 0, match.start()) + 1
                            code_snippet = lines[line_number - 1].strip()
                            
                            if key not in found_secrets:
                                found_secrets[key] = []
                            
                            found_secrets[key].append({
                                'value': secret_value,
                                'line_number': line_number,
                                'code_snippet': code_snippet,
                                'file_path': full_path
                            })
                            
                            secrets_found = True
    
    if verbose:
        if secrets_found:
            print("Found the following secrets:")
            for key, matches in found_secrets.items():
                print(f"{key}:")
                for match_info in matches:
                    print(f"  Value: {match_info['value']}")
                    print(f"  File Path: {match_info['file_path']}")
                    print(f"  Line Number: {match_info['line_number']}")
                    print(f"  Code Snippet: {match_info['code_snippet']}\n")
        else:
            print("No secrets found in any files.")
    
    return found_secrets

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_apk> [--verbose]")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    output_dir = f"{apk_name}.out"
    verbose = '--verbose' in sys.argv
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    decompile_apk(apk_path, output_dir, verbose)
    found_secrets = scan_for_secrets(output_dir, verbose)
    
    if verbose:
        print("Script execution completed.")

if __name__ == "__main__":
    main()
