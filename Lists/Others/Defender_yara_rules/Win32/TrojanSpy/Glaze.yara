rule TrojanSpy_Win32_Glaze_A_2147598325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Glaze.A"
        threat_id = "2147598325"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Glaze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 02 5f c6 06 4d 39 7d f8 c6 46 01 5a 76 23 89 5d fc 29 75 fc 8b c7 bb ff 00 00 00 99 f7 fb 8b 45 fc 8d 0c 37 8a 04 08 32 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Glaze_B_2147598326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Glaze.B"
        threat_id = "2147598326"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Glaze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 43 02 50 ff 15 ?? ?? 00 10 66 3d 15 00 (75|0f) [0-5] ff 73 04 ff 15 ?? ?? 00 10 80 a5 ?? ff ff ff 00 6a 31 8b ?? 59 33 c0 8d bd ?? ff ff ff f3 ab 66 ab aa [0-1] 8d 85 ?? ff ff ff 68 ?? ?? 00 10 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Glaze_C_2147611350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Glaze.C"
        threat_id = "2147611350"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Glaze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 08 80 f2 ?? 88 11 41 4f 75 f4}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2}  //weight: 5, accuracy: Low
        $x_10_3 = {66 3d 15 00 0f 85 ?? 00 00 00 53 ff 76 04 ff 15 ?? ?? 00 10 80 a5 ?? ff ff ff 00 6a 31 8b d8 59 33 c0 8d bd ?? ff ff ff f3 ab 66 ab aa 8d 85 ?? ff ff ff}  //weight: 10, accuracy: Low
        $x_1_4 = {61 6c 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

