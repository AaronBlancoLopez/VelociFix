import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import re

class LogFileEventHandler(FileSystemEventHandler):

    def __init__(self, file_path):
        self.file_path = file_path
        self._cached_stamp = os.stat(file_path).st_mtime
        self._file = open(file_path, "r")
        self._file.seek(0, os.SEEK_END)

    def on_modified(self, event):
        if event.src_path == self.file_path:
            new_stamp = os.stat(self.file_path).st_mtime
            if new_stamp != self._cached_stamp:
                self._cached_stamp = new_stamp
                self.notify_change()

    def notify_change(self):
        new_lines = self._file.readlines()
        get_request_pattern = re.compile(r'GET\s+/files/(\S+)\s+HTTP/\d\.\d"\s+(\d{3})')
        for line in new_lines:
            match = get_request_pattern.search(line)
            if match:
                file_name = match.group(1)
                status_code = match.group(2)
                if status_code == "200":
                    result = "found"
                elif status_code == "404":
                    result = "not found"
                else:
                    result = f"returned status {status_code}"
                print(f"File {file_name} was {result}")

    def __del__(self):
        self._file.close()

def monitor_log_file(file_path):
    event_handler = LogFileEventHandler(file_path)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(file_path), recursive=False)
    observer.start()
    print(f"Started monitoring {file_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    log_file_path = "/var/log/apache2/other_vhosts_access.log"
    monitor_log_file(log_file_path)
