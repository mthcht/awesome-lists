rule VirTool_Win32_Bofpless_A_2147901304_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofpless.A"
        threat_id = "2147901304"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofpless"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 41 65 c6 44 24 42 74 c6 44 24 43 43 c6 44 24 44 75 c6 44 24 45 72 c6 44 24 46 72 c6 44 24}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 4b 68 c6 44 24 4c 72 c6 44 24 4d 65 c6 44 24 4e 61 c6 44 24 4f 64 c6 44 24 50 00 48 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

