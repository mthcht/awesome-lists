rule VirTool_Win32_Dllhij_B_2147937399_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dllhij.B"
        threat_id = "2147937399"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhij"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 01 00 00 00 b8 4d 3c 2b 1a ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {56 57 89 c7 81 c6 62 04 00 00 b9 0d 00 00 00 f3 a4 5f 5e 8b 8d dc fd ff ff 89 48 07 8b 85 d8 fd ff ff 31 c9 66 8b 08 8b 45 08 29 c8 89 85 d0 fd ff ff 89 8d d4 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

