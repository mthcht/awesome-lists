rule VirTool_Win32_Cdknstubof_A_2147901295_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Cdknstubof.A"
        threat_id = "2147901295"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cdknstubof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "number of arguments" ascii //weight: 1
        $x_1_2 = "SHELLCODE" ascii //weight: 1
        $x_1_3 = "Spawning Temporary Process" ascii //weight: 1
        $x_1_4 = "Opening Existing Process" ascii //weight: 1
        $x_1_5 = "bofstop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

