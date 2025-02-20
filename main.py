from src.network_monitor_app import NetworkMonitorApp
from src.UI.monitoring_ui import NetworkMonitorUI

def main():
    app = NetworkMonitorApp()
    ui = NetworkMonitorUI(app)
    ui.run()

if __name__ == "__main__":
    main()
