rule VirTool_Win32_SuspRegRunInTempTarget_BT_2147956363_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRegRunInTempTarget.gen!BT"
        threat_id = "2147956363"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegRunInTempTarget"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe" wide //weight: 1
        $x_1_2 = " add " wide //weight: 1
        $x_1_3 = "\\AppData\\Local\\Temp\\" wide //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = " /v " wide //weight: 1
        $x_1_6 = " /d " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

