rule HackTool_Win32_ZhackDnsTunneling_A_2147773773_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ZhackDnsTunneling.A"
        threat_id = "2147773773"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ZhackDnsTunneling"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "d.zhack.ca" wide //weight: 10
        $x_1_2 = "powershell.exe" wide //weight: 1
        $x_1_3 = "cmd.exe" wide //weight: 1
        $x_1_4 = "ping.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

