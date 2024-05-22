import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

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
        if new_lines:
            print(f"New changes in {self.file_path}:")
            for line in new_lines:
                print(line.strip())

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





