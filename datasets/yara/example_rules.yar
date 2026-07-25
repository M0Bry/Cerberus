rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "high"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "downloadstring" nocase
        $d = "invoke-expression" nocase
    condition:
        $a and ($b or $c or $d)
}
