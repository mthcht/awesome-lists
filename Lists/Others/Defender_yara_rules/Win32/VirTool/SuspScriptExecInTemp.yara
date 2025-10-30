rule VirTool_Win32_SuspScriptExecInTemp_BT_2147956334_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspScriptExecInTemp.gen!BT"
        threat_id = "2147956334"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScriptExecInTemp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = " /c C:\\Users\\" wide //weight: 1
        $x_1_3 = "\\AppData\\Local\\Temp\\" wide //weight: 1
        $x_1_4 = ".vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

