rule VirTool_Win32_SuspPowershellReadExec_A_2147957700_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellReadExec.A"
        threat_id = "2147957700"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellReadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = " -c " wide //weight: 10
        $x_10_3 = "get-content " wide //weight: 10
        $x_10_4 = "| iex" wide //weight: 10
        $x_1_5 = " %TEMP%\\" wide //weight: 1
        $x_1_6 = "\\AppData\\Local\\Temp\\" wide //weight: 1
        $n_100_7 = "-ep Bypass " wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

