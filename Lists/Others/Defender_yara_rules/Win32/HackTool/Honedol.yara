rule HackTool_Win32_Honedol_A_2147683776_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Honedol.A"
        threat_id = "2147683776"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Honedol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HD All in One Tool V%s (%s)" ascii //weight: 10
        $x_10_2 = "Passw0rd" ascii //weight: 10
        $x_10_3 = "Code by William Henry" ascii //weight: 10
        $x_10_4 = "IPC$ Password Scanner" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

