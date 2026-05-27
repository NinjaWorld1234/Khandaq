from huggingface_hub import snapshot_download
import sys

try:
    print("Starting download of WhiteRabbitNeo-13B (GGUF Q4_K_M)...")
    snapshot_download(
        repo_id="TheBloke/WhiteRabbitNeo-13B-GGUF",
        allow_patterns=["*Q4_K_M*.gguf"],
        local_dir="/models/WhiteRabbitNeo-13B"
    )
    print("Download Complete!")
except Exception as e:
    print(f"Error during download: {e}")
    sys.exit(1)
