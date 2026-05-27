import os
import subprocess
from huggingface_hub import HfApi

def download_model(repo_id, local_dir):
    api = HfApi()
    files = api.list_repo_files(repo_id=repo_id)
    
    os.makedirs(local_dir, exist_ok=True)
    
    for file in files:
        # Construct the download URL
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file}"
        
        # Determine local file path
        local_file_path = os.path.join(local_dir, file)
        
        if os.path.exists(local_file_path):
            print(f"Skipping {file}, already exists or partially exists (aria2c will resume if needed)")
        
        # Ensure subdirectory exists
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
        
        print(f"Downloading {file} via aria2c...")
        cmd = [
            "aria2c",
            "--console-log-level=error",
            "--summary-interval=10",
            "-x", "16",
            "-s", "16",
            "-k", "1M",
            "-c",
            "-d", os.path.dirname(local_file_path),
            "-o", os.path.basename(local_file_path),
            url
        ]
        
        subprocess.run(cmd)

if __name__ == "__main__":
    import sys
    repo = sys.argv[1]
    dest = sys.argv[2]
    download_model(repo, dest)
