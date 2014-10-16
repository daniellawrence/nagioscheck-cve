#!/usr/bin/env python
"""
Simple nagios check for the big CVE issues
"""
import os
import sys

CRITICAL_RC = 2
OK_RC = 0


def cve_2014_3566():
    "Check for SSLv3 (Poodle)"
    check_poodle = "echo|timeout 3 openssl s_client -connect localhost:443 2>&1"
    result = os.popen(check_poodle).read()
    if 'Connection refused' in result:
        return False
    if 'sslv3 alert handshake failure' in result:
        return False
    return True


def cve_2014_6271():
    "Check for Bash (ShellShock)"
    check_shellshock = "env x='() { :;} echo vulnerable' bash -c 'echo'"
    result = os.popen(check_shellshock).read()
    if 'vulnerable' not in result:
        return False
    return True

# ------------------------------------------------------------------------------
# Loop over all the cve functions, print the results then exit
# ------------------------------------------------------------------------------
all_cve_results = {}
failures = []
for func_name, func in locals().items():
    if not func_name.startswith('cve'):
        continue
    func_result = func()
    all_cve_results[func_name] = func_result
    if func_result is True:
        failures.append(func_name)

if failures:
    print("Failed the following: %s" % ','.join(failures))
    sys.exit(CRITICAL_RC)

print("Passed all tests for: %s" % ",".join(all_cve_results.keys()))
sys.exit(OK_RC)
