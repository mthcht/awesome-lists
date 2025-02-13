rule VirTool_WinNT_Sichesh_A_2147678583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sichesh.A"
        threat_id = "2147678583"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sichesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 69 38 31 36 39 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 43 00 48 00 45 00 43 00 4b 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {b9 17 c0 20 04 3b c1 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 2d 07 c0 20 04 0f 84 ?? ?? ?? ?? 83 e8 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

