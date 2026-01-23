import argparse
import socket

import requests

from colorama import Fore, Back, Style, init

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved

def main():
    init(autoreset=True)
    print(Fore.YELLOW + "[INFO] Simple Web App Baseline Checker 10 Sep 2020. © CCK ")
    parser = argparse.ArgumentParser(description='Simple Cipher tester')
    parser.add_argument('-u', action="store", dest="url", type=str, help="Hostname or IP", required=True)
    args = parser.parse_args()
    url = args.url
    if "://" in url:
        print(Fore.RED + "[Error:] Wrong format. Hostname of IP only. Quiting.")
        return
    demo_synchronous_scanner(url)
    check_headers(url)
    # demo_concurrent_scanner()


def check_headers(purl):
    url = purl
    # print headers of response
    print(Fore.YELLOW + f"\n[INFO] Checking site response headers for {url} ...\n")

    try:
        response = requests.get('https://' + url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print(Fore.LIGHTRED_EX + "Http Error:", errh)
    #        return
    except requests.exceptions.ConnectionError as errc:
        print(Fore.LIGHTRED_EX + "Error Connecting:", errc)
        return
    except requests.exceptions.Timeout as errt:
        print(Fore.LIGHTRED_EX + "Timeout Error:", errt)
        return
    except requests.exceptions.RequestException as err:
        print(Fore.LIGHTRED_EX + "Exception:", err)
        return

    # print response
    # print(response)

    Great_Headers = [("X-Frame-Options", "SAMEORIGIN"),
                     ('X-XSS-Protection', "1; mode=block"),
                     ('X-Content-Type-Options', 'nosniff')
                     ]

    Headers = {
        "X-Frame-Options": "SAMEORIGIN",
        'X-XSS-Protection': "1; mode=block",
        'X-Content-Type-Options': 'nosniff'
    }

    # 'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
    # 'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
    # 'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},

    # 'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
    # 'server': {'defined': False, 'warn': 0, 'contents': ''}

    for res_header, value in Great_Headers:
        if res_header in response.headers.keys():
            if value == (response.headers[res_header]):
                print(Fore.LIGHTGREEN_EX + f"{res_header} = {response.headers[res_header]}")
            else:
                print(Fore.RED + f"{res_header} should be {value}, got {response.headers[res_header]}")
        else:
            print(Fore.RED + f"Warning!! Missing {res_header} --->> {Headers[res_header]}")

    if 'Strict-Transport-Security' in response.headers:
        hsts_value = response.headers['Strict-Transport-Security']
        if 'max-age' in hsts_value or 'includeSubDomains' in hsts_value or 'preload' in hsts_value:
            print(Fore.LIGHTGREEN_EX + f"Passed Strict-Transport-Security and value is {hsts_value}")
        else:
            print(Fore.RED + "Strict-Transport-Security should have value  max-age=31536000 ; includeSubDomains ; preload")
    else:
        print(Fore.RED + "Warning!! Missing Strict-Transport-Security header")

    if 'Set-Cookie' in response.headers:
        cookie_value = response.headers['Set-Cookie']
        if 'Secure' in cookie_value:
            print(Fore.LIGHTGREEN_EX + "Found Secure in Set-Cookie !")
        else:
            print(Fore.RED + "Secure missing in Set-Cookie!")

        if 'HTTPOnly' in cookie_value:
            print(Fore.LIGHTGREEN_EX + "Found HTTPOnly in Set-Cookie !")
        else:
            print(Fore.RED + "HTTPOnly missing in Set-Cookie!")
    else:
        print(Fore.RED + "Warning!! No Set-Cookie header present")

    print(f"\n[INFO] Dumping headers now \n")
    print(Fore.YELLOW + str(response.headers))


def demo_synchronous_scanner(url):
    SERVERS_TO_SCAN = []
    if url is not None:
        ttuple = (url, 443)
        SERVERS_TO_SCAN.append(ttuple)
    else:
        SERVERS_TO_SCAN = [
            ('www.mas.gov.sg', 443),
            ('www.moneysense.gov.sg', 443),
            ('eservices.mas.gov.sg', 443),
            ('masnet.mas.gov.sg', 443),
        ]

    BAD_Cipher = ["CBC", "CBC3", "3DES", "RC2", "RC4", "DES", "MD4", "MD5", "EXP", "EXP1024", "AH", "ADH", "aNULL",
                  "eNULL", "SEED", "IDE"]

    for hostname, port in SERVERS_TO_SCAN:
        try:
            scan_request = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=hostname, port=port)
            )

            print(Fore.YELLOW + f'\n[INFO] Checking supported ciphers of {hostname}:{port}...\n')

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            for server_scan_result in scanner.get_results():
                if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                    print(Fore.LIGHTRED_EX + f'[ERROR] Could not connect to {hostname}: {server_scan_result.connectivity_error_trace}')
                    exit(-1)

                assert server_scan_result.scan_result

                tls12_attempt = server_scan_result.scan_result.tls_1_2_cipher_suites
                if tls12_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls12_result = tls12_attempt.result
                    if len(tls12_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTGREEN_EX + "Supports TLS 1.2 ")
                    else:
                        print("No TLS 1.2 support.")

                    for cipher_suite in tls12_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

                tls13_attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
                if tls13_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls13_result = tls13_attempt.result
                    print(Fore.YELLOW + "\n[INFO] Testing TLS 1.3 ciphers now ...")
                    if len(tls13_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTGREEN_EX + "Supports TLS 1.3 ")
                    else:
                        print("No TLS 1.3 support.")

                    for cipher_suite in tls13_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

                tls11_attempt = server_scan_result.scan_result.tls_1_1_cipher_suites
                if tls11_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    print(Fore.YELLOW + "\n[INFO] Testing TLS 1.1 ciphers now ...")
                    tls11_result = tls11_attempt.result
                    if len(tls11_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTRED_EX + "Supports TLS 1.1 ")
                    else:
                        print(Fore.LIGHTGREEN_EX + "No TLS 1.1 supported.")

                    for cipher_suite in tls11_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

                tls10_attempt = server_scan_result.scan_result.tls_1_0_cipher_suites
                if tls10_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    print(Fore.YELLOW + "\n[INFO] Testing TLS 1.0 ciphers now ...")
                    tls10_result = tls10_attempt.result
                    if len(tls10_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTRED_EX + "Oh my TLS 1.0 supported .....")
                    else:
                        print(Fore.LIGHTGREEN_EX + "No TLS 1.0 supported.")

                    for cipher_suite in tls10_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

                ssl2_attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
                if ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    print(Fore.YELLOW + "\n[INFO] Testing SSL 2.0 ciphers now ...")
                    ssl2_result = ssl2_attempt.result
                    if len(ssl2_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTRED_EX + "Oh my SSL 2.0 supported .....")
                    else:
                        print(Fore.LIGHTGREEN_EX + "No SSL 2.0 supported.")

                    for cipher_suite in ssl2_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

                ssl3_attempt = server_scan_result.scan_result.ssl_3_0_cipher_suites
                if ssl3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    print(Fore.YELLOW + "\n[INFO] Testing SSL 3.0 ciphers now ...")
                    ssl3_result = ssl3_attempt.result
                    if len(ssl3_result.accepted_cipher_suites) > 0:
                        print(Fore.LIGHTRED_EX + "Oh my SSL 3.0 supported .....")
                    else:
                        print(Fore.LIGHTGREEN_EX + "No SSL 3.0 supported.")

                    for cipher_suite in ssl3_result.accepted_cipher_suites:
                        BAD = False
                        for item in BAD_Cipher:
                            if item in cipher_suite.cipher_suite.name:
                                BAD = True
                                break
                        if BAD:
                            print(Fore.LIGHTRED_EX + f' {cipher_suite.cipher_suite.name}')
                        else:
                            print(f' {cipher_suite.cipher_suite.name}')

        except ServerHostnameCouldNotBeResolved as e:
            print(Fore.LIGHTRED_EX + f'[ERROR] Could not resolve hostname {hostname}: {e}')
            exit(-1)
        except Exception as e:
            print(Fore.LIGHTRED_EX + f'[ERROR] Unexpected error: {e}')
            exit(-1)

    return


if __name__ == '__main__':
    main()