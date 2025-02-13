rule HackTool_Win32_Kitrap_A_2147631036_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Kitrap.A"
        threat_id = "2147631036"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitrap"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 1c 00 00 00 5a 89 50 04 8b 88 24 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 1c 00 00 00 8b 7d 58 8b 3f 8b 70 04 b9 84}  //weight: 1, accuracy: High
        $x_1_3 = {a1 1c f0 df ff 8b 7d 58 8b 3f 8b 88 24 01 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 a1 1c 00 00 00 8b 7d 58 8b 3f 8b 88 24 01 00}  //weight: 1, accuracy: High
        $x_1_5 = "NtVdmControl" ascii //weight: 1
        $x_1_6 = "VDMEXPLOIT.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

