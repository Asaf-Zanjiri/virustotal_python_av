# Python anti-virus - Virustotal API
A school assignment I got that seemed nice enough for github.


**Important Note:**

This application was developed as an educational exercise. It was not tested in extreme situations, however most situations should be covered.
This application is not secure, it does not verify who it talks to and if the input is sanitized.



**Features:**

- Listens to directory changes to detect when a file is being created.
- Communicates with virustotal's api to scan the file.
- Checks the file hash to see if it already exists in virustotal's database to save resources.
- Handles multiple files at the same time.
- Detects file types to see if they're worth scanning (Currently supports: EXE, DLL, PDF, ZIP, RAR, PNG, JPG, DOC...)
- Checks if the file is under the max upload size limit to virustotal and handles errors accordingly.
- Logs detection results to a file + link to a detailed report.



**Usage Guidelines:**

- Edit the PATH_TO_WATCH & PATH_TO_LOG constants in client.py
- Edit the API_KEY constant in server.py
- Smile :)
- Run server and then client. If there are errors try changing the server & client's port.

**Log file example:**
![image](https://user-images.githubusercontent.com/60044819/149026464-cec73df6-9d97-4911-9f97-8a68d7012e6d.png)



**Credits:**

timgolden - http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html
For an example on how to listen to directory changes via python.

