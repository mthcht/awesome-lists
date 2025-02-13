rule VirTool_Win32_Sunderlox_A_2147616809_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sunderlox.A"
        threat_id = "2147616809"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sunderlox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2f 00 2d 00 5c 00 70 00 4f 00 70 00 2f 00 2d 00 5c 00 00 00}  //weight: 4, accuracy: High
        $x_2_2 = "cmd.exe /c start rundll32.exe %SystemRoot%" wide //weight: 2
        $x_2_3 = {77 00 69 00 6e 00 33 00 32 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 73 00 4f 00 66 00}  //weight: 2, accuracy: High
        $x_2_4 = "Started log--" wide //weight: 2
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

