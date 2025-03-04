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
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 04 0d 8b d2 df 0d}  //weight: 1, accuracy: High
        $x_1_2 = {51 d3 b2 2a d8 fe 71 a9}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 00 00 00 00 ?? ?? ?? ?? 48 0b ?? e8 ?? ?? ?? ?? ?? ?? ?? 48 85 c0 74 ?? 48 35 ?? ?? ?? ?? 48 87 [0-16] 48 83 c4 20 ?? c3 48 35 [0-10] 48 83 c4 20 ?? c3}  //weight: 1, accuracy: Low
        $x_1_4 = "IsElevated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

