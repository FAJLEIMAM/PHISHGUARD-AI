import argparse
import os
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def run_command(command, cwd=PROJECT_ROOT, shell=True):
    print(f"Executing: {command}")
    try:
        subprocess.run(command, shell=shell, cwd=cwd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return False


def setup():
    print("\n=== [PhishGuard] Setting Up Environment ===")
    print("[1/2] Installing project in editable mode...")
    if not run_command(f'"{sys.executable}" -m pip install -e .'):
        return False

    print("[2/2] Synchronizing requirements...")
    if not run_command(f'"{sys.executable}" -m pip install -r requirements.txt'):
        return False

    print("\nSUCCESS: Environment synchronized. Modules are now discoverable.")
    return True


def cleanup_ports():
    """Checks for processes on ports 8000 and 8080 and terminates them if they exist."""
    ports = [8000, 8080]
    print("\n[PhishGuard] Checking for existing processes on ports 8000 and 8080...")

    for port in ports:
        try:
            # Get PID using netstat
            output = subprocess.check_output(
                f"netstat -ano | findstr :{port}", shell=True
            ).decode()
            for line in output.strip().split("\n"):
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    print(f"Port {port} is occupied by PID {pid}. Terminating...")
                    subprocess.run(f"taskkill /PID {pid} /F", shell=True, check=False)
        except subprocess.CalledProcessError:
            # No process found on this port
            pass


def run():
    cleanup_ports()
    print("\n=== [PhishGuard] Starting System ===")

    # Ensure setup is done (editable install check)
    try:
        import backend.main  # noqa: F401
    except ImportError:
        print("Project not installed in editable mode. Running setup first...")
        if not setup():
            return

    print("Starting Backend (Port 8000)...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "backend.main"], cwd=PROJECT_ROOT
    )

    print("Starting Frontend (Port 8080)...")
    frontend_dir = os.path.join(PROJECT_ROOT, "frontend")
    frontend_proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", "8080"], cwd=frontend_dir
    )

    print("\nSystem is running!")
    print("- Frontend: http://localhost:8080")
    print("- Backend:  http://localhost:8000")
    print("\nPress Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping system...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Stopped.")


def verify():
    print("\n=== [PhishGuard] Verifying System Logic ===")
    # Add project root to sys.path for verification if needed
    sys.path.append(PROJECT_ROOT)

    # Import and run the test flow from verify_fixes.py
    try:
        from verify_fixes import test_retraining_flow

        test_retraining_flow()
    except Exception as e:
        print(f"Verification Failed: {e}")
        return False
    return True


def clean():
    print("\n=== [PhishGuard] Cleaning Project ===")
    item_count = 0
    # Remove pycache and logs
    for root, dirs, files in os.walk(PROJECT_ROOT):
        for d in list(dirs):
            if d == "__pycache__":
                path = os.path.join(root, d)
                print(f"Removing {path}")
                shutil.rmtree(path)
                item_count += 1
        for f in files:
            if f.endswith(".egg-info") or f == "training_data_log.csv":
                path = os.path.join(root, f)
                print(f"Removing {path}")
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                item_count += 1
    print(f"Cleaned {item_count} items.")


def fix_ide():
    """Automates fixes for IDE import errors and cleans caches."""
    print("\n=== [PhishGuard] Fixing IDE Errors & Syncing Environment ===")

    # 1. Ensure all __init__.py files exist
    print("[1/4] Verifying project structure...")
    dirs_to_check = [
        os.path.join(PROJECT_ROOT, "backend"),
        os.path.join(PROJECT_ROOT, "backend", "core"),
        os.path.join(PROJECT_ROOT, "backend", "api"),
        os.path.join(PROJECT_ROOT, "backend", "integrations"),
    ]
    for d in dirs_to_check:
        init_file = os.path.join(d, "__init__.py")
        if not os.path.exists(init_file):
            print(f"Creating {init_file}")
            with open(init_file, "w") as f:
                f.write("# Init\n")

    # 2. Clean stale caches
    print("[2/4] Cleaning linter and python caches...")
    clean()
    pyre_cache = os.path.join(PROJECT_ROOT, ".pyre")
    if os.path.exists(pyre_cache):
        print(f"Removing {pyre_cache}")
        shutil.rmtree(pyre_cache)

    # 3. Refresh installation
    print("[3/4] Refreshing editable installation...")
    setup()

    # 4. Final verification
    print("[4/4] Verifying imports...")
    try:
        import backend.api.routes  # noqa: F401
        import backend.core.detector  # noqa: F401

        print("SUCCESS: Core modules are now correctly discoverable.")
    except ImportError as e:
        print(f"STILL MISSING: {e}")

    print("\nIDE FIX COMPLETE. Please restart your Python Language Server.")


def check():
    print("\n=== [PhishGuard] Running Quality Checks ===")

    print("\n[1/3] Formatting Check (Ruff)...")
    format_ok = run_command(f'"{sys.executable}" -m ruff format --check .')

    print("\n[2/3] Linting Check (Ruff)...")
    lint_ok = run_command(f'"{sys.executable}" -m ruff check .')

    print("\n[3/3] Running Tests (Pytest)...")
    tests_ok = run_command(f'"{sys.executable}" -m pytest tests/')

    if format_ok and lint_ok and tests_ok:
        print("\nALL CHECKS PASSED")
    else:
        print("\nSOME CHECKS FAILED. Run 'python phishguard.py fix'.")


def fix():
    print("\n=== [PhishGuard] Applying Auto-Fixes ===")
    print("\n[1/2] Formatting code...")
    run_command(f'"{sys.executable}" -m ruff format .')

    print("\n[2/2] Fixing lint issues...")
    run_command(f'"{sys.executable}" -m ruff check --fix .')
    print("\nFixes applied. Run 'python phishguard.py check' to verify.")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard AI X Automation CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    subparsers.add_parser("setup", help="Install project and dependencies")
    subparsers.add_parser("run", help="Start backend and frontend")
    subparsers.add_parser("verify", help="Run system verification tests")
    subparsers.add_parser("check", help="Run formatting, linting, and tests")
    subparsers.add_parser("fix", help="Automatically fix formatting and lint errors")
    subparsers.add_parser("clean", help="Remove temporary files and logs")
    subparsers.add_parser(
        "fix-ide", help="Automate fixes for IDE red lines/import errors"
    )

    args = parser.parse_args()

    if args.command == "setup":
        setup()
    elif args.command == "run":
        run()
    elif args.command == "verify":
        verify()
    elif args.command == "check":
        check()
    elif args.command == "fix":
        fix()
    elif args.command == "clean":
        clean()
    elif args.command == "fix-ide":
        fix_ide()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
