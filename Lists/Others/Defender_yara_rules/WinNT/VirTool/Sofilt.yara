rule VirTool_WinNT_Sofilt_A_2147629942_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sofilt.A"
        threat_id = "2147629942"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sofilt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 6d 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 43 00 61 00 6c 00 6c 00 62 00 61 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 46 00 69 00 6c 00 74 00 65 00 72 00 73 00 5c 00 44 00 25 00 58 00 25 00 58 00 43 00 44 00 4f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 04 8d 45 04 50 e8 ?? ?? ?? ?? 85 c0 74 05 8b 45 04 eb 3a ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 e8 00 00 00 00 58 e8 06 00 00 00 50 e8 1e 00 00 00 e8 00 00 00 00 58 83 c0 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

