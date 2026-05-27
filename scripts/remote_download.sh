#!/bin/bash
pip install -q huggingface_hub
huggingface-cli download TheBloke/WhiteRabbitNeo-13B-GGUF --include "*Q4_K_M*.gguf" --local-dir /models/WhiteRabbitNeo-13B
echo "Download Complete!"
