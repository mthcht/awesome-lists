rule TrojanSpy_Win64_Stilachi_A_2147935089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Stilachi.A"
        threat_id = "2147935089"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Stilachi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c8 04 0d 8b d2 df 0d}  //weight: 2, accuracy: High
        $x_2_2 = {51 d3 b2 2a d8 fe 71 a9}  //weight: 2, accuracy: High
        $x_2_3 = {48 b8 00 00 00 00 ?? ?? ?? ?? 48 0b ?? e8 ?? ?? ?? ?? ?? ?? ?? 48 85 c0 74 ?? 48 35 ?? ?? ?? ?? 48 87 [0-16] 48 83 c4 20 ?? c3 48 35 [0-10] 48 83 c4 20 ?? c3}  //weight: 2, accuracy: Low
        $x_1_4 = "IsElevated" ascii //weight: 1
        $x_1_5 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 [0-64] 73 71 6c 69 74 65 33 5f 61 67 67 72 65 67 61 74 65 5f 63 6f 6e 74 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

