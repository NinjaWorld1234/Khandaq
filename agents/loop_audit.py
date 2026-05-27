import subprocess
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python loop_audit.py <target_file> [--reset]")
    sys.exit(1)

target = sys.argv[1]
reset = "--reset" in sys.argv

state_file = ".critic_state.json"
if reset and os.path.exists(state_file):
    print("Resetting state file...")
    os.remove(state_file)

count = 0
while count < 20:
    res = subprocess.run(["python", "auto_supervisor.py", target], capture_output=True, text=True)
    print(res.stdout)
    
    if res.returncode == 1:
        print(f"--- STOPPED AT FAILURE IN ITERATION {count+1} ---")
        sys.exit(1)
        
    if res.returncode == 3:
        print(f"--- LOOP PAUSED: COGNITIVE HOLD REACHED ---")
        print(f"Waiting for semantic agent review before proceeding.")
        sys.exit(0)
        
    if "TARGET IS FULLY SECURE ACROSS ALL 5 PHASES" in res.stdout:
        print(f"--- GOLDEN REACHED IN ITERATION {count+1} ---")
        sys.exit(0)
        
    count += 1
