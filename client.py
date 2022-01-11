import os
import time

import win32file
import win32con
import threading
from socket_modules import Client

FILE_CREATED_ACTION = 0x0001
FILE_LIST_DIRECTORY = 0x0001
PATH_TO_WATCH = 'EDIT_ME'   # Example - C:\Users\admin\Downloads
PATH_TO_LOG = 'EDIT_ME'     # Example - C:\Users\admin\Downloads


def detect_file(header):
    """
     Check a file header against common malicious file types to determine if the file is worth scanning.
    :param header: File header to compare signatures against.
    :return: True if it's a file type worth scanning, else False.
    """
    # Common malicious file types by signature. This list is limited to save resources and avoid exceeding the api request limit.
    sigs = [b'MZ', b'ZM', b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', b'\x50\x4B\x03\x04', b'\x25\x50\x44\x46\x2D', b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\xFF\xD8\xFF', b'\x52\x61\x72\x21\x1A\x07']
    for sig in sigs:
        if header[:len(sig)] == sig:
            return True
    return False


def capture_response(client):
    """
    Captures messages sent from the servers and saves them to results.txt
    :param client: Client object from 'socket_modules'
    """
    while True:
        response = client.receive(raw_response=True)
        print('[!] Received scan report - adding to log file.')
        with open(PATH_TO_LOG + '\\log.txt', 'ab') as f:
            f.write(response)
            f.write('-------------------------------------------\n'.encode())


def main():
    client = Client('localhost', 4444)
    threading.Thread(target=capture_response, args=(client,)).start()

    # Listen to directory changes.
    hDir = win32file.CreateFile(PATH_TO_WATCH, FILE_LIST_DIRECTORY, win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE, None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_BACKUP_SEMANTICS, None)
    while True:
        try:
            results = win32file.ReadDirectoryChangesW(hDir, 1024, True, win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_SIZE | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE, None, None)
            for action, file in results:
                if action == FILE_CREATED_ACTION:
                    full_filename = os.path.join(PATH_TO_WATCH, file)
                    print('[*] File created - ', full_filename)
                    time.sleep(1)
                    try:
                        with open(full_filename, 'rb') as f:
                            header = f.read(8)
                        if detect_file(header):
                            print('[*] Sending the file to analysis...')
                            client.send(full_filename)
                        else:
                            print('[*] File type detected as less likely to contain malware - Skipping scan to save resources.')
                    except Exception as e:
                        print('[!] Error - ', e)

        except Exception as e:
            print('[!] Error - ', e)
            break

    client.close()


if __name__ == '__main__':
    main()

# Note: This application is not secure, it does not verify who it talks to and if the input is sanitized.
