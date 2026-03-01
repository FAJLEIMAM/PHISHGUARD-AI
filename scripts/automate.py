import argparse
import subprocess
import sys
import time


def run_command(command, description):
    print(f"\n[Running] {description}...")
    try:
        result = subprocess.run(command, shell=True, check=False)
        if result.returncode == 0:
            print(f"[Success] {description} passed.")
            return True
        else:
            print(
                f"[Failure] {description} failed with return code {result.returncode}."
            )
            return False
    except Exception as e:
        print(f"[Error] Failed to run {description}: {e}")
        return False


def run_all_checks():
    success = True
    success &= run_command("python -m ruff format --check .", "Formatting check (Ruff)")
    success &= run_command("python -m ruff check .", "Linting check (Ruff)")
    success &= run_command("python -m pyright", "Type checking (Pyright)")
    success &= run_command("python -m pytest tests/", "Running Tests (Pytest)")

    if success:
        print("\n[ALL CHECKS PASSED]")
    else:
        print("\n[SOME CHECKS FAILED]")
    return success


def watch_mode():
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        print(
            "Error: 'watchdog' package not found. "
            "Please install it with 'pip install watchdog'."
        )
        sys.exit(1)

    class ChangeHandler(FileSystemEventHandler):
        def __init__(self):
            self.last_run: float = 0.0
            self.debounce_seconds = 2

        def on_any_event(self, event):
            if event.is_directory:
                return
            path = str(event.src_path)
            if not path.endswith((".py", ".js", ".html", ".css")):
                return

            current_time = time.time()
            if current_time - self.last_run > self.debounce_seconds:
                print(f"\n[Change Detected] {event.src_path}")
                run_all_checks()
                self.last_run = current_time

    print("Starting watch mode... Press Ctrl+C to stop.")
    run_all_checks()  # Run once at start

    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate code quality checks.")
    parser.add_argument("--watch", action="store_true", help="Run in watch mode.")
    args = parser.parse_args()

    if args.watch:
        watch_mode()
    else:
        run_all_checks()
        sys.exit(0 if run_all_checks() else 1)
