rule VirTool_Win32_SuspPowershellUnblockFileExec_A_2147956333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellUnblockFileExec.gen!A"
        threat_id = "2147956333"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellUnblockFileExec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -c " wide //weight: 1
        $x_1_3 = "Unblock-File " wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\Temp\\" wide //weight: 1
        $x_1_5 = ".ps1'; & " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

