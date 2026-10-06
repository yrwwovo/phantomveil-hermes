$ErrorActionPreference = 'Stop'
$forkRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$entry = Join-Path $forkRoot '.venv\Scripts\pveil.exe'
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
    throw 'PhantomVeil fork 未安装：缺少 .venv\Scripts\pveil.exe'
}
& $entry @args
exit $LASTEXITCODE
