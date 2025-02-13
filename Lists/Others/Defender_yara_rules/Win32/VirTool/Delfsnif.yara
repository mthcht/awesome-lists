rule VirTool_Win32_Delfsnif_2147597477_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Delfsnif"
        threat_id = "2147597477"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db 8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75 a5}  //weight: 2, accuracy: High
        $x_2_2 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d ?? ?? ?? ?? 88 c3 32 de c1 e8 08 33 04 9d}  //weight: 2, accuracy: Low
        $x_2_3 = {89 f9 83 e1 03 e3 11 88 c3 32 1e c1 e8 08 46 33 04 9d ?? ?? ?? ?? e2 ef 35 ff ff ff ff}  //weight: 2, accuracy: Low
        $x_4_4 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 4
        $x_5_5 = "WriteProcessMemory" ascii //weight: 5
        $x_4_6 = "VirtualAllocEx" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

