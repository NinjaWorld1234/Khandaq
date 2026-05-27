# Script to pull and save all Docker images offline for Air-Gapped deployment
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$composeDir = Join-Path $scriptDir "docker"
$exportDir = Join-Path $scriptDir "soc_offline_images"

Write-Host "Checking export directory: $exportDir"
if (!(Test-Path $exportDir)) {
    New-Item -ItemType Directory -Force -Path $exportDir | Out-Null
}

# Find all docker-compose*.yml files
$composeFiles = Get-ChildItem -Path $composeDir -Filter "docker-compose*.yml" -Recurse

$images = @()

foreach ($file in $composeFiles) {
    # Extract image names from the yaml files
    $content = Get-Content $file.FullName
    foreach ($line in $content) {
        if ($line -match '^\s*image:\s*(.+)$') {
            $rawImg = $matches[1] -replace '["'']', ''
            
            # Resolve ${VAR:-default} syntax
            if ($rawImg -match '\$\{[^:]+:-([^}]+)\}') {
                $rawImg = $rawImg -replace '\$\{[^:]+:-([^}]+)\}', '$1'
            }
            
            # Exclude specific heavy/standalone images just like bash script
            if ($rawImg -notmatch "soc-ai-agents|greenbone|tpotce") {
                $images += $rawImg
            }
        }
    }
}

# Remove duplicates
$images = $images | Select-Object -Unique

Write-Host "Found $($images.Count) unique images to download."
Write-Host "------------------------------------------------"

foreach ($img in $images) {
    Write-Host "Pulling image: $img ..." -ForegroundColor Cyan
    docker pull $img
    
    if ($?) {
        # Replace slashes and colons with underscores for the filename
        $safeName = $img -replace '[/:]', '_'
        $tarPath = Join-Path $exportDir "$safeName.tar"
        
        Write-Host "Saving $img to $tarPath ..." -ForegroundColor Yellow
        docker save -o $tarPath $img
        Write-Host "Done saving $safeName.tar" -ForegroundColor Green
    } else {
        Write-Host "Failed to pull $img" -ForegroundColor Red
    }
    Write-Host "------------------------------------------------"
}

Write-Host "All images processed! You can find the .tar files in $exportDir" -ForegroundColor Green
Write-Host "To load them on the server later, run: docker load -i <filename.tar>"
