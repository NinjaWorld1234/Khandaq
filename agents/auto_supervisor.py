import sys
import os
import subprocess
import json

STATE_FILE = ".critic_state.json"
PHASES = ["structural", "logical", "evasion", "operational", "deep_sweep"]

def run():
    if len(sys.argv) < 2:
        print("Usage: python auto_supervisor.py <target_file> [--approve-cognitive]")
        sys.exit(1)

    target_file = sys.argv[1]
    approve_cognitive = "--approve-cognitive" in sys.argv
    
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
    else:
        state = {"file": target_file, "current_phase_index": 0, "consecutive_passes": 0, "cognitive_pending": False}
        
    if state.get("file") != target_file:
        state = {"file": target_file, "current_phase_index": 0, "consecutive_passes": 0, "cognitive_pending": False}

    # Handle explicit cognitive approval from the AI
    if approve_cognitive:
        if state.get("cognitive_pending"):
            state["cognitive_pending"] = False
            state["current_phase_index"] += 1
            state["consecutive_passes"] = 0
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            print("==========================================")
            print("[COGNITIVE APPROVED] PROCEEDING TO NEXT PHASE")
            print("==========================================")
            sys.exit(0)
        else:
            print("No cognitive hold is currently pending. Ignoring approval flag.")
            sys.exit(0)

    phase_index = state.get("current_phase_index", 0)
    if phase_index >= len(PHASES):
        print(f"==========================================")
        print(f"[GOLDEN] TARGET IS FULLY SECURE ACROSS ALL 5 PHASES")
        print(f"==========================================")
        print(f"Target: {target_file} has mathematically passed the Multi-Phase Actor-Critic loop.")
        sys.exit(0)

    # If we are pending a cognitive hold, we block execution until the AI approves it
    if state.get("cognitive_pending"):
        print(f"==========================================")
        print(f"[COGNITIVE HOLD] WAITING FOR MANUAL AI SEMANTIC AUDIT")
        print(f"==========================================")
        print(f"Phase {PHASES[phase_index].upper()} automated checks passed.")
        print(f"AGENT COMMAND: You MUST now perform a Deep Cognitive/Semantic review of the file.")
        print(f"When finished and verified, run 'python auto_supervisor.py {target_file} --approve-cognitive' to unlock the next phase.")
        sys.exit(3)

    current_phase = PHASES[phase_index]
    print(f"=== RUNNING PHASE: {current_phase.upper()} ===")

    critic_script = os.path.join(os.path.dirname(__file__), "soc_critic_agent.py")
    result = subprocess.run(["python", critic_script, target_file, "--phase", current_phase], capture_output=True, text=True)
    
    if result.returncode != 0:
        state["consecutive_passes"] = 0
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
        print(f"==========================================")
        print(f"[FAILED] CRITIC FAILED IN PHASE: {current_phase.upper()} (Passes reset to 0)")
        print(f"==========================================")
        print(result.stdout)
        print(f"AGENT COMMAND: You MUST fix the above logical errors in {target_file}.")
        print(f"After applying the fixes, you MUST run 'python auto_supervisor.py {target_file}' again.")
        sys.exit(1)
    else:
        state["consecutive_passes"] += 1
        
        if state["consecutive_passes"] >= 2:
            print(f"==========================================")
            print(f"[PHASE COMPLETE] {current_phase.upper()} SUCCESS: 2 CONSECUTIVE PASSES")
            print(f"==========================================")
            
            # Instead of advancing immediately, trigger a Cognitive Hold
            state["cognitive_pending"] = True
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            
            print(f"==========================================")
            print(f"[COGNITIVE HOLD INITIATED]")
            print(f"==========================================")
            print(f"AGENT COMMAND: Stop automated execution. You MUST now deeply read the file and fix rooted semantic sub-errors for phase {current_phase.upper()}.")
            print(f"When ready, resume by running: python auto_supervisor.py {target_file} --approve-cognitive")
            sys.exit(3)
        else:
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            print(f"==========================================")
            print(f"[WARNING] PHASE {current_phase.upper()} PASSED (1/2)")
            print(f"==========================================")
            print(f"Target: {target_file} passed, but requires one more consecutive pass in this phase.")
            print(f"AGENT COMMAND: Do NOT modify the file. You MUST run 'python auto_supervisor.py {target_file}' exactly one more time to confirm.")
            sys.exit(2)

if __name__ == "__main__":
    run()
