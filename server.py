import requests
import hashlib
from os.path import getsize
from socket_modules import Server
from time import sleep
import threading

# Consts
VT_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_KEY = 'EDIT_ME'
VT_MAX_FILESIZE = 32000000
SCAN_WAIT_TIME = 65


def md5(file_path):
    """
    Generates MD5 checksum for a given path.
    :param file_path:
    :return: File's md5 hash
    """
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def check_scan_results(file_hash):
    """
    Tries to obtain file scan results.
    :param file_hash: Hash of the file to get the scan results of.
    :return: None if no results were found. Else response dictionary.
    """
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(VT_REPORT_URL, params=params).json()
    if response['response_code'] == 1:
        return response
    else:
        return None


def scan_file(file_path, file_name):
    """
    Uploads a file to virustotal to get scanned.
    :param file_path: File path to scan.
    :param file_name: File name.
    :return: True if upload was successful, else False.
    """
    params = {'apikey': API_KEY}
    with open(file_path, 'rb') as f:
        files = {'file': (file_name, f)}
        response = requests.post(VT_SCAN_URL, files=files, params=params).json()
    if response['response_code'] == 1 or response['response_code'] == -2:
        return True
    return False


def capture_response(server, file_path):
    """
    Captures messages sent from the client and handles them accordingly.
    :param server: Server object from 'socket_modules'
    :param file_path: File path to scan.
    """
    try:
        file_name = file_path.rsplit('\\', 1)[-1]
        file_hash = md5(file_path)
        result = f'[!] Report: {file_path}\n'
        print(f'[*] Received file {file_name} - Starting to scan.')

        # Check if the file is already in the virustotal database.
        response = check_scan_results(file_hash)
        if response:
            result += f'- Detected {response["positives"]} viruses - Full report: {response["permalink"]}\n'
        else:
            # Check if it's possible to scan the file.
            if getsize(file_path) >= VT_MAX_FILESIZE:
                result += '- File size exceeds max upload size. Cant scan.\n'
            else:
                # Scan file
                if scan_file(file_path, file_name):
                    result += '- Uploaded file successfully.\n'
                    sleep(SCAN_WAIT_TIME)
                    # Retrieve scan results.
                    response = check_scan_results(file_hash)
                    if response:
                        result += f'- Detected {response["positives"]} viruses - Full report: {response["permalink"]}\n'
                    else:
                        result += '- Problem occurred while retrieving scan results.\n'
                else:
                    result += '- Problem occurred when uploading file.\n'
        print(result)
        server.send(result)
    except Exception as e:
        print('[!] Error - ', e)


def main():
    server = Server('0.0.0.0', 4444)
    while True:
        try:
            file_path = server.receive()
            threading.Thread(target=capture_response, args=(server, file_path,)).start()
        except Exception as e:
            print('[!] Error - ', e)
            break
    server.close()


if __name__ == '__main__':
    main()
