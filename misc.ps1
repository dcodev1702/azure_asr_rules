[String[]]$Rule = 'lorenzo','ireland','john'

$Rule | ForEach-Object {
    Write-Output "RULES FROM RUN_ASR() -> $_ " | Out-File -FilePath "C:\tmp\asr_debug.txt" -Append
}