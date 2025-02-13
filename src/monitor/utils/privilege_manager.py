from src.monitor.utils.utils import setup_logger
import platform
import ctypes
import os
import sys

class PrivilegeManager:
    def __init__(self):
        self.logger = setup_logger("PrivilegeManager")
        self.child_process = []
    
    def is_admin(self) -> bool:
        try:
            if platform.system() == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
        
    def elevate_if_needed(self) -> bool:
        if not self.is_admin():
            try:
                if platform.system() == 'Windows':
                    self.logger.info("Requesting administrator privileges...")
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",
                        sys.executable,
                        " ".join(sys.argv),
                        None,
                        1
                    )
                    sys.exit()
                return False
            except Exception as e:
                self.logger.error(f"Failed to elevate privilege: {e}")
                return False
        return True
    
    
    #Might need later on down the line...
    
    def register_process(self, process):
        self.child_process.append(process)

    def cleanup(self):
        for process in self.child_process:
            try:
                self.logger.info(f"Attempting to terminate process PID: {process.pid}")
                process.terminate()
                process.wait(timeout=5)
                self.logger.info(f"Successfully terminated process PID: {process.pid}")
            except Exception as e:
                self.logger.warning(f"Termination failed for PID {process.pid}. Trying to kill. Error: {e}")
                try:
                    process.kill()
                    self.logger.info(f"Successfully killed process PID: {process.pid}")
                except Exception as kill_err:
                    self.logger.error(f"Failed to kill process PID {process.pid}. Error: {kill_err}")