from app.watcher.folder_watcher import start_watcher
import time


def main():
    observer = start_watcher()

    if observer:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    main()
