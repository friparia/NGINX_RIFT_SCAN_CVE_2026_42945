import subprocess
import re
import sys

AFFECTED_MIN_VERSION = (0, 6, 27)
AFFECTED_MAX_VERSION = (1, 30, 0)
AFFECTED_RANGE_TEXT = "0.6.27 - 1.30.0"


def get_nginx_version():
    try:
        # nginx -v outputs to stderr
        proc = subprocess.Popen(['nginx', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = proc.communicate()
        version_output = stderr.decode('utf-8') if sys.version_info[0] >= 3 else stderr
        return version_output.strip()
    except:
        return "Unable to run nginx -v"


def parse_nginx_version(version_output):
    match = re.search(r'nginx/(\d+\.\d+\.\d+)', version_output)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split('.'))


def get_version_status(version_output):
    version = parse_nginx_version(version_output)
    if version is None:
        return (None, "Unable to parse current version. Affected NGINX Open Source range: " + AFFECTED_RANGE_TEXT)

    if AFFECTED_MIN_VERSION <= version <= AFFECTED_MAX_VERSION:
        return (True, "Affected version range for NGINX Open Source (" + AFFECTED_RANGE_TEXT + ")")

    return (False, "Outside affected version range for NGINX Open Source (" + AFFECTED_RANGE_TEXT + ")")


def load_config():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            return f.read()

    try:
        proc = subprocess.Popen(['nginx', '-T'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            print("Error: unable to dump NGINX config with nginx -T. Run with sudo or pass a config file path.")
            return None
        return stdout.decode('utf-8') if sys.version_info[0] >= 3 else stdout
    except Exception as e:
        print("Error executing nginx -T: " + str(e))
        return None


def report_block_if_vulnerable(block_lines):
    re_rewrite_with_args = re.compile(r'\brewrite\s+[^;]*\([^;]*\)[^;]*\?[^;]*;')
    re_followup_capture = re.compile(r'\b(?:rewrite|if|set)\b[^;]*\$[1-9][0-9]*[^;]*;')

    has_seen_rewrite_with_args = False
    vulnerable_in_order = False
    trigger_lines = []

    for b_line in block_lines:
        if re_rewrite_with_args.search(b_line):
            has_seen_rewrite_with_args = True
            trigger_lines.append("[1. Rewrite With ?] " + b_line)
        elif has_seen_rewrite_with_args and re_followup_capture.search(b_line):
            vulnerable_in_order = True
            trigger_lines.append("[2. Follow-up $N]   " + b_line)

    if vulnerable_in_order:
        print("\n[!] VULNERABLE SEQUENCE FOUND:")
        print("    Context: " + block_lines[0])
        for t in trigger_lines:
            print("    " + t)
        return True

    return False


def scan_nginx_rift():
    print("--- NGINX Rift Config Scanner (CVE-2026-42945) ---")
    
    version = get_nginx_version()
    version_affected, version_status = get_version_status(version)
    print("Current NGINX Version: " + version)
    print("Version Status: " + version_status)
    
    config = load_config()
    if config is None:
        return

    lines = config.splitlines()
    block_stack = []
    risk_found = False

    for line in lines:
        clean_line = line.strip()
        if not clean_line or clean_line.startswith('#'):
            continue

        if '{' in clean_line:
            block_stack.append([clean_line])
            continue

        if '}' in clean_line:
            if block_stack:
                block_lines = block_stack.pop()
                if report_block_if_vulnerable(block_lines):
                    risk_found = True
            continue

        if block_stack:
            block_stack[-1].append(clean_line)

    if not risk_found:
        print("\n[+] No vulnerable CVE-2026-42945 sequences detected.")
        if version_affected is True:
            print("\n[Recommendation]: Current NGINX version is in the affected range, but no vulnerable config sequence was detected. Upgrade is recommended, but config risk was not found by this scanner.")
        elif version_affected is None:
            print("\n[Recommendation]: Verify the NGINX version manually. Affected NGINX Open Source versions are " + AFFECTED_RANGE_TEXT + ".")
    else:
        if version_affected is True:
            print("\n[Action Required]: Current NGINX version is affected and vulnerable config was found. Upgrade NGINX or adjust the reported rewrite/if/set sequence.")
        elif version_affected is False:
            print("\n[Review Required]: Vulnerable config pattern was found, but the current NGINX Open Source version is outside the affected range. Keep the patched version and review whether this config can be simplified.")
        else:
            print("\n[Action Required]: Vulnerable config pattern was found, but the NGINX version could not be verified. Check the version immediately; if it is " + AFFECTED_RANGE_TEXT + ", upgrade NGINX or adjust the reported config.")

if __name__ == "__main__":
    scan_nginx_rift()
