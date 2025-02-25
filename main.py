# main.py
from src.network_monitor_app import NetworkMonitorApp
from src.UI.monitoring_ui import NetworkMonitorUI
import ctypes
import sys
import win32event
import win32api
import logging

def ensure_single_instance():
    """Check if another instance is running using a mutex."""
    mutex_name = 'Global\\NetworkMonitorApp'
    try:
        mutex = win32event.CreateMutex(None, True, mutex_name)
        if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            logging.basicConfig(level=logging.INFO)
            logging.error("Another instance of the application is already running.")
            sys.exit(1)
        return mutex
    except Exception as e:
        logging.basicConfig(level=logging.INFO)
        logging.error(f"Failed to create mutex: {e}")
        sys.exit(1)

def main():
    # Ensure single instance before doing anything
    mutex = ensure_single_instance()

    # Check if we need elevation
    if sys.platform == 'win32' and not ctypes.windll.shell32.IsUserAnAdmin():
        logging.basicConfig(level=logging.INFO)
        logging.info("Not running as admin; elevating privileges...")
        # Elevate with SW_HIDE (0) to avoid CMD window
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 0)
        sys.exit(0)

    # If we reach here, we're either admin or don't need elevation
    app = NetworkMonitorApp()
    ui = NetworkMonitorUI(app)
    ui.run()

    # Cleanup mutex on exit
    win32api.CloseHandle(mutex)

if __name__ == "__main__":
    main()