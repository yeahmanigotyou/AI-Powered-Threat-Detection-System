import tkinter as tk
import threading

class NetworkMonitorUI:
    def __init__(self, app):
        self.app = app
        self.window = tk.Tk()
        self.window.title("Network Monitoring Control")
        
        # Create start and stop buttons
        self.start_button = tk.Button(self.window, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)
        
        self.stop_button = tk.Button(self.window, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=10)
        
        # Create status label
        self.status_label = tk.Label(self.window, text="Status: Stopped", fg="red")
        self.status_label.pack(pady=10)
        
        self.stop_event = threading.Event()
        self.monitor_thread = None

    def update_status(self, status):
        """Update the status label in the UI."""
        self.status_label.config(text=f"Status: {status}")
        if status == "Running":
            self.status_label.config(fg="green")
        else:
            self.status_label.config(fg="red")

    def start_monitoring(self):
        """Start monitoring in a separate thread to avoid blocking the UI."""
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.update_status("Running")
        
        # Start monitoring in a new thread
        self.monitor_thread = threading.Thread(target=self.app.start_monitoring)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring and update UI."""
        self.app.stop_monitoring()
        self.update_status("Stopped")
        
        if self.monitor_thread:
            self.monitor_thread.join()
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def run(self):
        """Start the Tkinter event loop."""
        self.window.mainloop()
