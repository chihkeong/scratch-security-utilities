from cryptography.x509 import NameOID
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand

from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.synchronous_scanner import SynchronousScanner
import argparse
import socket
import requests

from colorama import Fore, Back, Style, init
from colored import fore
from sty import fg, bg, ef, rs

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
                print(Fore.RED + "X-Frame-Options should be SAMEORIGIN")
        else:
            print(Fore.RED + f"Warning!! Missing {res_header} --->> {Headers[res_header]}")

    if 'max-age' in response.headers['Strict-Transport-Security'] or 'includeSubDomains ; preload' in response.headers[
        'Strict-Transport-Security']:
        print(
            Fore.LIGHTGREEN_EX + f"Passed Strict-Transport-Security and value is {response.headers['Strict-Transport-Security']}")
    else:
        print(Fore.RED + "Strict-Transport-Security should have value  max-age=31536000 ; includeSubDomains ; preload")

    if 'Secure' in response.headers['Set-Cookie']:
        print(Fore.LIGHTGREEN_EX + "Found Secure in Set-Cookie !")
    else:
        print(Fore.RED + "Secure missing in Set-Cookie!")

    if 'HTTPOnly' in response.headers['Set-Cookie']:
        print(Fore.LIGHTGREEN_EX + "Found HTTPOnly in Set-Cookie !")
    else:
        print(Fore.RED + "HTTPOnly missing in Set-Cookie!")

    print(f"\n[INFO] Dumping headers now \n")
    print(Fore.YELLOW + str(response.headers))


def demo_server_connectivity_tester():
    try:

        server_tester = ServerConnectivityTester(
            hostname='www.mas.gov.sg',
            port=443,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        print(f'\nTesting connectivity with {server_tester.hostname}:{server_tester.port}...')
        server_info = server_tester.perform()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError(f'Could not connect to {e.server_info.hostname}: {e.error_message}')

    return server_info


def demo_synchronous_scanner(url):
    SERVERS_TO_SCAN = []
    if url is not None:
        ttuple = (url, 443, TlsWrappedProtocolEnum.HTTPS)
        SERVERS_TO_SCAN.append(ttuple)
    # Run one scan command to list the server's TLS 1.0 cipher suites
    else:
        SERVERS_TO_SCAN = [
            ('www.mas.gov.sg', 443, TlsWrappedProtocolEnum.HTTPS),
            ('www.moneysense.gov.sg', 443, TlsWrappedProtocolEnum.HTTPS),
            ('eservices.mas.gov.sg', 443, TlsWrappedProtocolEnum.HTTPS),
            ('masnet.mas.gov.sg', 443, TlsWrappedProtocolEnum.HTTPS),
            # ('vodafone.de', 443, TlsWrappedProtocolEnum.HTTPS),  # This one is vulnerable as of 12/17/2017
        ]

    BAD_Cipher = ["CBC", "CBC3", "3DES", "RC2", "RC4", "DES", "MD4", "MD5", "EXP", "EXP1024", "AH", "ADH", "aNULL",
                  "eNULL", "SEED", "IDE"]
    for hostname, port, protocol in SERVERS_TO_SCAN:
        try:
            server_tester = ServerConnectivityTester(
                hostname=hostname,
                port=port,
                tls_wrapped_protocol=protocol
            )
            print(
                Fore.YELLOW + f'\n[INFO] Checking supported ciphers of {server_tester.hostname}:{server_tester.port}...\n')
            server_info = server_tester.perform()
        except ServerConnectivityError as e:
            # Could not establish an SSL connection to the server
            print(Fore.LIGHTRED_EX + f'[ERROR] Could not connect to {e.server_info.hostname}: {e.error_message}')
            exit(-1)
        except socket.gaierror as e:
            print(Fore.LIGHTRED_EX + f'[ERROR] Wrong hostname/IP format  {e.server_info.hostname}: {e.error_message}')
            exit(-1)
        command = Tlsv12ScanCommand()

        synchronous_scanner = SynchronousScanner()

        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        BAD = False
        if len(scan_result.accepted_cipher_list) > 0:
            print(Fore.LIGHTGREEN_EX + "Supports TLS 1.2 ")
        else:
            print("No TLS 1.2 support.")
        for cipher in scan_result.accepted_cipher_list:
            for item in BAD_Cipher:
                if item in cipher.name:
                    BAD = True
                    break
            if BAD:
                print(Fore.LIGHTRED_EX + f' {cipher.name}')
            else:
                print(f' {cipher.name}')
            BAD = False

        command = Tlsv11ScanCommand()
        print(Fore.YELLOW + "\n[INFO] Testing TLS 1.1 ciphers now ...")
        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        if len(scan_result.accepted_cipher_list) > 0:
            print(Fore.LIGHTRED_EX + "Supports TLS 1.1 ")
        else:
            print(Fore.LIGHTGREEN_EX + "No TLS 1.1 supported.")

        for cipher in scan_result.accepted_cipher_list:
            for item in BAD_Cipher:
                if item in cipher.name:
                    BAD = True
                    break
            if BAD:
                print(Fore.LIGHTRED_EX + f' {cipher.name}')
            else:
                print(f' {cipher.name}')
            BAD = False

        command = Tlsv10ScanCommand()
        print(Fore.YELLOW + "\n[INFO] Testing TLS 1.0 ciphers now ...")
        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        if len(scan_result.accepted_cipher_list) > 0:
            print(Fore.LIGHTRED_EX + "Oh my TLS 1.0 supported ..... ")
        else:
            print(Fore.LIGHTGREEN_EX + "No TLS 1.0 supported.")

        for cipher in scan_result.accepted_cipher_list:
            for item in BAD_Cipher:
                if item in cipher.name:
                    BAD = True
                    break
            if BAD:
                print(Fore.LIGHTRED_EX + f' {cipher.name}')
            else:
                print(f' {cipher.name}')
            BAD = False

        command = Sslv20ScanCommand()
        print(Fore.YELLOW + "\n[INFO] Testing SSL 2.0 ciphers now ...")
        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        if len(scan_result.accepted_cipher_list) > 0:
            print(Fore.LIGHTRED_EX + "Oh my SSL 2.0 supported ..... ")
        else:
            print(Fore.LIGHTGREEN_EX + "No SSL 2.0 supported.")

        for cipher in scan_result.accepted_cipher_list:
            for item in BAD_Cipher:
                if item in cipher.name:
                    BAD = True
                    break
            if BAD:
                print(Fore.LIGHTRED_EX + f' {cipher.name}')
            else:
                print(f' {cipher.name}')
            BAD = False

        command = Sslv30ScanCommand()
        print(Fore.YELLOW + "\n[INFO] Testing SSL 3.0 ciphers now ...")
        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        if len(scan_result.accepted_cipher_list) > 0:
            print(Fore.LIGHTRED_EX + "Oh my SSL 3.0 supported ..... ")
        else:
            print(Fore.LIGHTGREEN_EX + "No SSL 3.0 supported.")

        for cipher in scan_result.accepted_cipher_list:
            for item in BAD_Cipher:
                if item in cipher.name:
                    BAD = True
                    break
            if BAD:
                print(Fore.LIGHTRED_EX + f' {cipher.name}')
            else:
                print(f' {cipher.name}')
            BAD = False

    return


def demo_concurrent_scanner():
    # Setup the server to scan and ensure it is online/reachable
    server_info = demo_server_connectivity_tester()

    # Run multiple scan commands concurrently. It is much faster than the SynchronousScanner
    concurrent_scanner = ConcurrentScanner()

    # Queue some scan commands
    print('\nQueuing some commands...')
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())

    # Process the results
    print('\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
        # All scan results have the corresponding scan_command and server_info as an attribute
        print(
            f'\nReceived result for "{scan_result.scan_command.get_title()}" 'f'on {scan_result.server_info.hostname}')

        # A scan command can fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            raise RuntimeError(f'Scan command failed: {scan_result.scan_command.get_title()}')

        # Each scan result has attributes with the information yo're looking for
        # All these attributes are documented within each scan command's module
        if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                print(f' {cipher.name}')

        elif isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            # Print the Common Names within the verified certificate chain
            if not scan_result.verified_certificate_chain:
                print('Error: certificate chain is not trusted!')
            else:
                print('Certificate chain common names:')
                for cert in scan_result.verified_certificate_chain:
                    cert_common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    print(f' {cert_common_names[0].value}')


if __name__ == '__main__':
    main()



# from sslyze.synchronous_scanner import SynchronousScanner
# from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand, Tlsv11ScanCommand, Tlsv10ScanCommand, Sslv30ScanCommand, Sslv20ScanCommand
# from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
#
# server_info = ServerConnectivityInfo(hostname='www.test.de', port=443)
# server_info.test_connectivity_to_server()
#
# sslv20 = { 'version': 'SSLv20', 'command': Sslv20ScanCommand() }
# sslv30 = { 'version': 'SSLv30', 'command': Sslv30ScanCommand() }
# tlsv10 = { 'version': 'TLSv10', 'command': Tlsv10ScanCommand() }
# tlsv11 = { 'version': 'TLSv11', 'command': Tlsv11ScanCommand() }
# tlsv12 = { 'version': 'TLSv12', 'command': Tlsv12ScanCommand() }
#
# while True:
# for protocol in [sslv20, sslv30, tlsv10, tlsv11, tlsv12]:
# scanner = SynchronousScanner(network_timeout=2, network_retries=2)
# scan_result = scanner.run_scan_command(server_info, protocol['command'])
# print(scan_result)