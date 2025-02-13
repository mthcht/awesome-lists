rule VirTool_WinNT_Piptim_2147606927_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Piptim"
        threat_id = "2147606927"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Piptim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {90 90 33 c0 8b 00 c3}  //weight: 1, accuracy: High
        $x_10_2 = {8b 42 01 8b 0d 10 40 01 00 8b 11 c7 04 82 ?? ?? 01 00 e8 ?? ?? ff ff fb c7 05 ?? 60 01 00 01 00 00 00 eb 43 83 7d 08 00 75 3d 83 3d ?? 60 01 00 01 75 34 fa a1 ?? 40 01 00 8b 48 01 8b 15 10 40 01 00 8b 02 8b 15 ?? 60 01 00 89 14 88}  //weight: 10, accuracy: Low
        $x_1_3 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

