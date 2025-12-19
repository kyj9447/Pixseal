# compile_extension.ps1
[CmdletBinding()]
param(
  [string]$Python = "python",
  [string]$ProjectRoot = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Require-Command($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Command '$name' not found. Set -Python to your python.exe"
  }
}

$pkgDir = Join-Path $ProjectRoot "pip_package"
$pyx    = Join-Path $pkgDir "Pixseal/simpleImage_ext.pyx"

Require-Command $Python
Write-Host "[build] using python: $Python"

# Cython check
@'
import importlib.util, sys
if importlib.util.find_spec("Cython") is None:
    sys.exit("Cython is not installed. Run: python -m pip install -U cython")
'@ | & $Python -

Write-Host "[build] cythonizing and building in-place..."
& $Python -m Cython.Build.Cythonize -i $pyx

# cleanup
$genC = Join-Path $pkgDir "Pixseal/simpleImage_ext.c"
$eggInfo = Join-Path $pkgDir "Pixseal.egg-info"
$buildDir = Join-Path $ProjectRoot "build"
$pkgBuildDir = Join-Path $pkgDir "build"
Remove-Item $genC -ErrorAction SilentlyContinue
Remove-Item $eggInfo -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $buildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $pkgBuildDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[build] done. Look for simpleImage_ext*.pyd under $pkgDir\Pixseal"
