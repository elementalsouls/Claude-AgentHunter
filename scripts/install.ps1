<#
  Claude-AgentHunter installer (Windows / PowerShell) — copies the skills into each agent
  harness's skill dir. Mirror of scripts/install.sh, same verified routing:

    Claude Code (baseline)  ~\.claude\skills\            (default)
    OpenCode                reads ~\.claude\skills + ~\.agents\skills   (default | -Agents)
    OpenAI Codex CLI        ~\.agents\skills\            (-Agents)
    Hermes Agent            ~\.hermes\skills\            (-Hermes)
    Google AntiGravity      ~\.gemini\config\skills\     (-AntiGravity)

  The skills port to all five. The slash commands and the engine/lab stay Claude-Code /
  standalone by design. Only the Claude Code path is verified end-to-end.

  Usage: pwsh ./scripts/install.ps1 [-All] [-Claude] [-Agents] [-Hermes] [-AntiGravity]
#>
param(
  [switch]$All,
  [switch]$Claude,
  [switch]$Agents,
  [switch]$Hermes,
  [switch]$AntiGravity
)
$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSScriptRoot
$Skills  = Join-Path $RepoDir 'skills'

function Dir-For([string]$name) {
  switch ($name) {
    'claude'      { Join-Path $HOME '.claude\skills' }
    'agents'      { Join-Path $HOME '.agents\skills' }        # Codex CLI + OpenCode secondary
    'hermes'      { Join-Path $HOME '.hermes\skills' }
    'antigravity' { Join-Path $HOME '.gemini\config\skills' }
    default       { '' }
  }
}

function Install-To([string]$name) {
  $dir = Dir-For $name
  if (-not $dir) { Write-Host "  ! unknown target: $name"; return }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $n = 0
  foreach ($s in Get-ChildItem -Directory $Skills) {
    Copy-Item -Recurse -Force $s.FullName (Join-Path $dir $s.Name)
    $n++
  }
  Write-Host "  + $name -> $dir  ($n skills)"
}

function Detect {
  'claude'   # baseline, always
  if ((Get-Command codex -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.agents')) `
      -or (Test-Path (Join-Path $HOME '.codex')) -or (Test-Path (Join-Path $HOME '.config\opencode'))) { 'agents' }
  if ((Get-Command hermes -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.hermes'))) { 'hermes' }
  if ((Get-Command antigravity -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.gemini'))) { 'antigravity' }
}

if ($Claude)      { Install-To 'claude' }
elseif ($Agents)  { Install-To 'agents' }
elseif ($Hermes)  { Install-To 'hermes' }
elseif ($AntiGravity) { Install-To 'antigravity' }
else              { foreach ($h in (Detect)) { Install-To $h } }   # -All / no flag

$count = (Get-ChildItem -Directory $Skills).Count
Write-Host "done. $count skills available."
